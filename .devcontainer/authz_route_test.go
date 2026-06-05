package main

// Hermetic integration tests that drive the REAL handler against a fake upstream (no Docker
// daemon). They pin two assessment fixes at the transport/routing layer, where a pure
// checkCreate test can't reach:
//
//   - path-cleaning: a privileged create sent on a NON-CANONICAL path (`//containers/create`,
//     `/foo/../containers/create`, ...) is policed and DENIED at the shim -- it must never
//     reach the upstream as a create (assessment recommendation 1).
//   - read-endpoint gating: GET export/logs/top/changes/inspect of a container OUTSIDE our
//     project is denied; a same-project / owned target is allowed through (finding F1).

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUpstream records every request path it parses and replies per a caller-supplied
// responder. Returns the listener address (host, port) and a snapshot func.
func fakeUpstream(t *testing.T, respond func(path string) string) (host, port string, seen func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					c.SetReadDeadline(time.Now().Add(2 * time.Second))
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					mu.Lock()
					paths = append(paths, req.URL.Path)
					mu.Unlock()
					io.Copy(io.Discard, req.Body)
					io.WriteString(c, respond(req.URL.Path))
				}
			}(conn)
		}
	}()
	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return h, p, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), paths...) }
}

// rawRequest sends one request line + headers (+ optional body) to the shim and returns the
// raw response.
func rawRequest(t *testing.T, shimURL, reqLine string, headers map[string]string, body string) string {
	t.Helper()
	cc, err := net.Dial("tcp", strings.TrimPrefix(shimURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	var b strings.Builder
	// Connection: close so the shim/server closes after responding -> io.ReadAll returns
	// at once instead of blocking on the keep-alive read deadline (keeps the suite fast).
	b.WriteString(reqLine + "\r\nHost: d\r\nConnection: close\r\n")
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if body != "" {
		fmt.Fprintf(&b, "Content-Type: application/json\r\nContent-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n" + body)
	if _, err := cc.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	out, _ := io.ReadAll(cc)
	return string(out)
}

func TestHandlerPolicesNonCanonicalCreate(t *testing.T) {
	host, port, seen := fakeUpstream(t, func(string) string {
		return "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"
	})
	defer func(s, h, p string) { upSock, upHost, upPort = s, h, p }(upSock, upHost, upPort)
	upSock, upHost, upPort = "", host, port

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	priv := `{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/host"]}}`
	for _, dirty := range []string{"//containers/create", "/containers//create", "/foo/../containers/create", "/./containers/create"} {
		resp := rawRequest(t, srv.URL, "POST "+dirty+" HTTP/1.1", nil, priv)
		if !strings.Contains(resp, "403") {
			t.Errorf("dirty create %q was not denied (resp: %q)", dirty, firstLine(resp))
		}
	}
	for _, p := range seen() {
		if strings.Contains(p, "containers/create") {
			t.Fatalf("a privileged create reached the upstream via a non-canonical path (seen: %v)", seen())
		}
	}
}

func TestHandlerGatesCrossProjectReads(t *testing.T) {
	// Upstream inspect: "ours" is owned, "theirs" is a sibling project, others 404.
	host, port, seen := fakeUpstream(t, func(p string) string {
		body := ""
		switch {
		case strings.HasPrefix(p, "/containers/ours/json"):
			body = `{"Config":{"Labels":{"authz.owned":"project:alpha"}}}`
		case strings.HasPrefix(p, "/containers/mate/json"):
			body = `{"Config":{"Labels":{"com.docker.compose.project":"alpha"}}}`
		case strings.HasPrefix(p, "/containers/theirs/json"):
			body = `{"Config":{"Labels":{"com.docker.compose.project":"beta","authz.owned":"project:beta"}}}`
		}
		if body == "" {
			return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
		}
		return "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	})
	defer func(s, h, p string) { upSock, upHost, upPort = s, h, p }(upSock, upHost, upPort)
	upSock, upHost, upPort = "", host, port
	upstreamTransport.CloseIdleConnections() // drop stale pooled conns to a prior test's upstream
	defer func(o, pr string) { ownerID, ourProject = o, pr }(ownerID, ourProject)
	ownerID, ourProject = "project:alpha", "alpha"

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	// cross-project export/logs/inspect: denied
	for _, ep := range []string{"export", "logs", "top", "changes", "json"} {
		resp := rawRequest(t, srv.URL, "GET /containers/theirs/"+ep+" HTTP/1.1", nil, "")
		if !strings.Contains(resp, "403") {
			t.Errorf("cross-project GET /containers/theirs/%s was not denied (resp: %q)", ep, firstLine(resp))
		}
	}
	// our own + same-project: allowed through to the upstream
	for _, id := range []string{"ours", "mate"} {
		resp := rawRequest(t, srv.URL, "GET /containers/"+id+"/export HTTP/1.1", nil, "")
		if strings.Contains(resp, "403") {
			t.Errorf("readable GET /containers/%s/export was wrongly denied (resp: %q)", id, firstLine(resp))
		}
	}
	// image export (docker save) is denied outright -- and must not reach the upstream
	resp := rawRequest(t, srv.URL, "GET /images/alpine/get HTTP/1.1", nil, "")
	if !strings.Contains(resp, "403") {
		t.Errorf("image export was not denied (resp: %q)", firstLine(resp))
	}
	for _, p := range seen() {
		if strings.HasPrefix(p, "/images/") {
			t.Errorf("image export reached the upstream: %q", p)
		}
		if strings.HasPrefix(p, "/containers/theirs/") && !strings.HasSuffix(p, "/json") {
			t.Errorf("a cross-project read reached the upstream: %q", p)
		}
	}
}

// TestHandlerGatesCrossProjectNetworks pins the cont.20 pivot fix: a create/connect/inspect
// touching ANOTHER project's network is denied; our own project's network is allowed. This is
// the cooperative half of the fix (the primary half -- the shim off the network onto a unix
// socket -- is a topology property, asserted by test-escape.sh, not reachable from here).
func TestHandlerGatesCrossProjectNetworks(t *testing.T) {
	host, port, seen := fakeUpstream(t, func(p string) string {
		body := ""
		switch {
		case strings.HasPrefix(p, "/networks/alpha_dev"): // ours
			body = `{"Labels":{"com.docker.compose.project":"alpha"}}`
		case strings.HasPrefix(p, "/networks/beta_dev"): // foreign
			body = `{"Labels":{"com.docker.compose.project":"beta"}}`
		case strings.HasPrefix(p, "/containers/create"):
			return "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"
		}
		if body == "" {
			return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
		}
		return "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	})
	defer func(s, h, p string) { upSock, upHost, upPort = s, h, p }(upSock, upHost, upPort)
	upSock, upHost, upPort = "", host, port
	// The handler's inspect client shares the package-global upstreamTransport, which pools
	// keep-alive conns by the constant URL host "upstream" -- a stale conn to a PRIOR test's
	// (now-closed) fake would fail the inspect closed. Drop idle conns before we start.
	upstreamTransport.CloseIdleConnections()
	defer func(o, pr string) { ownerID, ourProject = o, pr }(ownerID, ourProject)
	ownerID, ourProject = "project:alpha", "alpha"

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	// connect / inspect / create onto the FOREIGN network: denied
	denyCases := []struct{ name, reqLine, body string }{
		{"connect-foreign", "POST /networks/beta_dev/connect HTTP/1.1", `{"Container":"x"}`},
		{"disconnect-foreign", "POST /networks/beta_dev/disconnect HTTP/1.1", `{"Container":"x"}`}, // F4
		{"inspect-foreign", "GET /networks/beta_dev HTTP/1.1", ""},
		{"create-foreign-netmode", "POST /containers/create HTTP/1.1", `{"Image":"alpine","HostConfig":{"NetworkMode":"beta_dev"}}`},
		{"create-foreign-endpoint", "POST /containers/create HTTP/1.1", `{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"beta_dev":{}}}}`},
	}
	for _, c := range denyCases {
		resp := rawRequest(t, srv.URL, c.reqLine, nil, c.body)
		if !strings.Contains(resp, "403") {
			t.Errorf("%s was not denied (resp: %q)", c.name, firstLine(resp))
		}
	}
	// our OWN network: allowed through
	allowCases := []struct{ name, reqLine, body string }{
		{"connect-own", "POST /networks/alpha_dev/connect HTTP/1.1", `{"Container":"x"}`},
		{"disconnect-own", "POST /networks/alpha_dev/disconnect HTTP/1.1", `{"Container":"x"}`}, // F4
		{"inspect-own", "GET /networks/alpha_dev HTTP/1.1", ""},
		{"create-own-netmode", "POST /containers/create HTTP/1.1", `{"Image":"alpine","HostConfig":{"NetworkMode":"alpha_dev"}}`},
	}
	for _, c := range allowCases {
		resp := rawRequest(t, srv.URL, c.reqLine, nil, c.body)
		if strings.Contains(resp, "403") {
			t.Errorf("%s was wrongly denied (resp: %q)", c.name, firstLine(resp))
		}
	}
	// A foreign create must NEVER reach the upstream. We sent two foreign creates (both
	// denied) and one own-network create (allowed), so EXACTLY one create should have
	// reached the upstream -- proving the two foreign creates were stopped at the shim.
	creates := 0
	for _, p := range seen() {
		if strings.Contains(p, "containers/create") {
			creates++
		}
	}
	if creates != 1 {
		t.Errorf("expected exactly 1 create to reach upstream (the own-network one), got %d", creates)
	}
}

// TestHandlerGatesForeignLifecycle pins the cont.20 integrity fix: stop/kill/restart/rename
// and `docker rm` are owned-only (symmetric with exec/cp). A foreign container's lifecycle
// can't be driven; our own created container's can.
func TestHandlerGatesForeignLifecycle(t *testing.T) {
	host, port, _ := fakeUpstream(t, func(p string) string {
		body := ""
		switch {
		case strings.HasPrefix(p, "/containers/mine/json"):
			body = `{"Config":{"Labels":{"authz.owned":"project:alpha"}}}`
		case strings.HasPrefix(p, "/containers/theirs/json"):
			body = `{"Config":{"Labels":{"com.docker.compose.project":"beta","authz.owned":"project:beta"}}}`
		}
		if body == "" {
			return "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
		}
		return "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	})
	defer func(s, h, p string) { upSock, upHost, upPort = s, h, p }(upSock, upHost, upPort)
	upSock, upHost, upPort = "", host, port
	upstreamTransport.CloseIdleConnections() // drop stale pooled conns to a prior test's upstream
	defer func(o, pr string) { ownerID, ourProject = o, pr }(ownerID, ourProject)
	ownerID, ourProject = "project:alpha", "alpha"

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	// foreign lifecycle: denied
	for _, rl := range []string{
		"POST /containers/theirs/start HTTP/1.1", // F6: start joins the owned-only set
		"POST /containers/theirs/stop HTTP/1.1",
		"POST /containers/theirs/kill HTTP/1.1",
		"POST /containers/theirs/rename HTTP/1.1",
		"DELETE /containers/theirs HTTP/1.1",
	} {
		resp := rawRequest(t, srv.URL, rl, nil, "")
		if !strings.Contains(resp, "403") {
			t.Errorf("foreign lifecycle %q was not denied (resp: %q)", rl, firstLine(resp))
		}
	}
	// our own: allowed
	for _, rl := range []string{
		"POST /containers/mine/start HTTP/1.1", // F6
		"POST /containers/mine/stop HTTP/1.1",
		"DELETE /containers/mine HTTP/1.1",
	} {
		resp := rawRequest(t, srv.URL, rl, nil, "")
		if strings.Contains(resp, "403") {
			t.Errorf("owned lifecycle %q was wrongly denied (resp: %q)", rl, firstLine(resp))
		}
	}
}

// TestHandlerGatesDestructiveEndpoints pins the deny-by-default control-plane fixes:
//   F7  prune (containers/volumes/images/networks/build) is daemon-global -> denied
//   F8  the PLURAL `docker save` (/images/get?names=) -> denied
//   F10 macvlan/ipvlan + host-parent network create -> denied; a plain bridge create allowed
// None of the denied requests may reach the upstream.
func TestHandlerGatesDestructiveEndpoints(t *testing.T) {
	host, port, seen := fakeUpstream(t, func(string) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	})
	defer func(s, h, p string) { upSock, upHost, upPort = s, h, p }(upSock, upHost, upPort)
	upSock, upHost, upPort = "", host, port
	upstreamTransport.CloseIdleConnections() // drop stale pooled conns to a prior test's upstream

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	denied := []struct{ name, reqLine, body string }{
		{"containers-prune", "POST /containers/prune HTTP/1.1", ""},
		{"volumes-prune", "POST /volumes/prune HTTP/1.1", ""},
		{"images-prune", "POST /images/prune HTTP/1.1", ""},
		{"networks-prune", "POST /networks/prune HTTP/1.1", ""},
		{"build-prune", "POST /build/prune HTTP/1.1", ""},
		{"docker-save-plural", "GET /images/get?names=alpine HTTP/1.1", ""},
		{"macvlan-create", "POST /networks/create HTTP/1.1", `{"Driver":"macvlan"}`},
		{"host-parent-create", "POST /networks/create HTTP/1.1", `{"Driver":"bridge","Options":{"parent":"eth0"}}`},
	}
	for _, c := range denied {
		resp := rawRequest(t, srv.URL, c.reqLine, nil, c.body)
		if !strings.Contains(resp, "403") {
			t.Errorf("%s was not denied (resp: %q)", c.name, firstLine(resp))
		}
	}
	// a plain bridge network create is still allowed (reaches the upstream)
	resp := rawRequest(t, srv.URL, "POST /networks/create HTTP/1.1", nil, `{"Driver":"bridge","Name":"mynet"}`)
	if strings.Contains(resp, "403") {
		t.Errorf("plain bridge network create was wrongly denied (resp: %q)", firstLine(resp))
	}
	for _, p := range seen() {
		if strings.HasSuffix(p, "/prune") || p == "/images/get" {
			t.Errorf("a denied destructive endpoint reached the upstream: %q", p)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		return s[:i]
	}
	return s
}
