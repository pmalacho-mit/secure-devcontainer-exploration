package main

// Hermetic regression test for the hijack-path request-smuggling guard (cont.8/cont.11,
// the test-escape `/session` case). No Docker daemon: a fake upstream stands in for
// tecnativa+daemon and records every request it receives. The exploit pipelines a
// privileged, host-root-binding `POST /containers/create` directly behind an
// upgrade-flagged `POST /session`; we assert the create NEVER reaches the upstream.

import (
	"bufio"
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

func TestHijackSmugglingGuard(t *testing.T) {
	// Fake upstream: parse each request on the connection and record its path, replying
	// 400 (keep-alive) like tecnativa does for /session. If the guard were broken, the
	// smuggled create would arrive as the next request on THIS connection and be recorded.
	var mu sync.Mutex
	var seen []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
					seen = append(seen, req.URL.Path)
					mu.Unlock()
					io.Copy(io.Discard, req.Body)
					io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
				}
			}(conn)
		}
	}()

	// Point the shim at the fake upstream (TCP fallback path; no unix socket here).
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func(s, h, p string) { upSock, upHost, upPort = s, h, p }(upSock, upHost, upPort)
	upSock, upHost, upPort = "", host, port

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	// Raw-dial the shim and send the pipelined exploit in one write.
	caddr := strings.TrimPrefix(srv.URL, "http://")
	cc, err := net.Dial("tcp", caddr)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	body := `{"Image":"alpine","Cmd":["true"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}`
	exploit := "POST /session HTTP/1.1\r\nHost: d\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n" +
		"POST /containers/create?name=smuggle HTTP/1.1\r\nHost: d\r\n" +
		"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	if _, err := cc.Write([]byte(exploit)); err != nil {
		t.Fatal(err)
	}
	// Drain responses until the shim closes / a short idle timeout.
	cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.Copy(io.Discard, cc)

	mu.Lock()
	defer mu.Unlock()
	for _, p := range seen {
		if strings.Contains(p, "/containers/create") {
			t.Fatalf("smuggled create reached the upstream (paths seen: %v)", seen)
		}
	}
	// The /session request itself should have reached the upstream (sanity: the guard
	// dropped the pipelined bytes, not the legitimate first request).
	if len(seen) == 0 || !strings.HasSuffix(seen[0], "/session") {
		t.Fatalf("expected the upstream to see /session first, got: %v", seen)
	}
}
