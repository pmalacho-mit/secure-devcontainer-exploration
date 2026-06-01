// authz-proxy.go
// Body-inspecting Docker gate, Go port of the former authz-proxy.py.
//
//	app  (DOCKER_HOST=tcp://docker-authz:2375)
//	  -> this shim            (polices create/exec/volume-create/attach/cp/build by content)
//	    -> docker-endpoint-proxy  (tecnativa: coarse endpoint ACL, holds the real socket,
//	       reached over a unix socket; tecnativa is OFF all networks -- cont.10)
//	      -> /var/run/docker.sock
//
// WHY GO (cont.16). The Python shim approximated the daemon's request parsing with a
// SECOND, different parser (Python's `re` on the raw path, `str.lower()`, `dict`). Every
// place the two parsers disagreed was an escape:
//
//	cont.14  shim matched body keys case-SENSITIVELY; the daemon (Go encoding/json)
//	         matches struct fields case-INSENSITIVELY      ->  `binds` vs `Binds`
//	cont.15  shim folded keys with str.lower(); the daemon folds with bytes.EqualFold
//	         (Unicode-aware: long-s, Kelvin)               ->  `Bindſ`
//	Finding M  shim matched the RAW request path; the daemon routes the URL-DECODED path
//	                                                        ->  `/containers/%63reate`
//
// This port removes the differential CLASS by construction: it parses the request with
// THE SAME stdlib the daemon uses.
//   - Path: net/http decodes %xx into r.URL.Path, so routing sees exactly what the daemon
//     routes (Finding M gone -- no raw-path regex).
//   - Body: we unmarshal into the daemon's own api/types structs, so Go's encoding/json
//     does the IDENTICAL case-insensitive / Unicode-aware field matching the daemon does
//     (`binds`, `BINDS`, `Bindſ` all land in HostConfig.Binds -> caught by the one check).
//     The whole canon_keys / case_collision / has_nonascii_key apparatus is gone.
//   - Framing: net/http + httputil.ReverseProxy read exactly one request per connection
//     and handle the exec/attach/session upgrade handshake and build/cp streaming. The
//     hand-rolled HTTP plumbing (read_headers/content_length/is_chunked/is_upgrade/
//     rewrite/relay/pump) and the request-smuggling guards (cont.8, cont.11) are gone --
//     the stdlib does not hand pipelined bytes to the next stage.
//
// Policy is unchanged from the Python shim: a sibling may not have MORE access than the
// dev container -- no privileged, no added capabilities, no devices, no host/cross-
// container namespaces, NO host paths mounted in at all (every bind and every host-bind
// `local`-volume `device` is denied; plain daemon-managed volumes and tmpfs are fine),
// no custom seccomp/apparmor, no privileged exec, and it may not reach the gate socket
// volume or the (now non-existent) gate network. Containers we create are stamped
// `authz.owned=1`; exec/attach/`docker cp` are allowed only into those. Fail closed.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// ---- config / upstream ------------------------------------------------------

const ownLabel = "authz.owned"

var (
	// cont.10: reach tecnativa over a unix-domain socket on a shared volume. tecnativa
	// then runs `network_mode: none` (off ALL bridges), so no build/sibling netns has an
	// IP to route to. UPSTREAM_HOST/PORT remain as a TCP fallback (used by the DESIGN's
	// "throwaway shim chained in front of the running one" live-validation pattern).
	upSock = os.Getenv("UPSTREAM_SOCK")
	upHost = envOr("UPSTREAM_HOST", "docker-endpoint-proxy")
	upPort = envOr("UPSTREAM_PORT", "2375")

	// The gate network/volume name patterns (Compose project-prefixes them). Under a unix
	// upstream the gate network does not exist; the suffix check is a cheap, harmless
	// backstop and isGateVol still matters (the socket lives on the gate-sock volume).
	gateNetRe = regexp.MustCompile(`(^|[-_])gate$`)
	gateVolRe = regexp.MustCompile(`(^|[-_])gate-sock$`)

	// Routing patterns run against the DECODED path (r.URL.Path). The daemon also accepts
	// an optional /vX.Y API-version prefix, which we allow here too.
	createRe    = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/create$`)
	execRe      = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/exec$`)
	attachRe    = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/attach(?:/ws)?$`)
	archiveRe   = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/archive$`)
	connectRe   = regexp.MustCompile(`^/(?:v[0-9.]+/)?networks/([^/]+)/connect$`)
	volCreateRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?volumes/create$`)
	buildRe     = regexp.MustCompile(`^/(?:v[0-9.]+/)?build$`)
	// Connection-hijack endpoints (exec start, BuildKit /session) that upgrade to a raw
	// bidirectional stream. attach (also a hijack) is matched by attachRe so it can be
	// ownership-gated first. These are handled by handleHijack (NOT ReverseProxy), whose
	// built-in upgrade copier returns on the FIRST direction's EOF -- which truncates a
	// non-interactive `docker exec`'s stdout the instant the client half-closes stdin.
	hijackRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?(?:exec/[^/]+/start|session)$`)
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func dialUpstream(ctx context.Context, _, _ string) (net.Conn, error) {
	d := &net.Dialer{}
	if upSock != "" {
		return d.DialContext(ctx, "unix", upSock)
	}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(upHost, upPort))
}

// Plain HTTP/1.1 transport over the unix socket (no env proxy, no h2). httputil's
// upgrade handling and the ownership-query client both ride this.
var upstreamTransport = &http.Transport{DialContext: dialUpstream}

var upstreamClient = &http.Client{Transport: upstreamTransport}

var proxy = &httputil.ReverseProxy{
	Director: func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = "upstream"
		// Emit the canonical DECODED path we judged, so the daemon can never route a
		// byte sequence the shim didn't classify (the Finding M invariant: judged path
		// == forwarded path == routed path).
		req.URL.RawPath = ""
	},
	Transport: upstreamTransport,
}

// ---- create policy ----------------------------------------------------------

// createBody mirrors the daemon's container.CreateRequest exactly (an embedded *Config
// promotes Image/Cmd/Labels/... to the top level, with HostConfig/NetworkingConfig
// nested) -- but is defined locally so we don't depend on the wrapper type's name across
// moby versions. The security-relevant structs (Config, HostConfig, mount.Mount,
// network.NetworkingConfig) ARE the daemon's own, so encoding/json folds keys identically.
type createBody struct {
	*container.Config
	HostConfig       *container.HostConfig     `json:"HostConfig,omitempty"`
	NetworkingConfig *network.NetworkingConfig `json:"NetworkingConfig,omitempty"`
}

func decodeCreate(body []byte) (*createBody, error) {
	var c createBody
	err := json.Unmarshal(body, &c)
	return &c, err
}

// checkCreate returns a deny reason, or "" to allow.
func checkCreate(c *createBody) string {
	if hc := c.HostConfig; hc != nil {
		if hc.Privileged {
			return "privileged"
		}
		if len(hc.CapAdd) > 0 {
			return "adds capabilities"
		}
		if len(hc.Devices) > 0 || len(hc.DeviceRequests) > 0 || len(hc.DeviceCgroupRules) > 0 {
			return "device passthrough"
		}
		if len(hc.VolumesFrom) > 0 {
			return "VolumesFrom (could inherit the proxy socket)"
		}
		// Any non-empty value shares a namespace -- denied (the dev container shares none).
		if hc.PidMode != "" {
			return "shares namespace: pidmode"
		}
		if hc.IpcMode != "" {
			return "shares namespace: ipcmode"
		}
		if hc.UTSMode != "" {
			return "shares namespace: utsmode"
		}
		if hc.UsernsMode != "" {
			return "shares namespace: usernsmode"
		}
		nm := string(hc.NetworkMode)
		if low := strings.ToLower(nm); low == "host" || strings.HasPrefix(low, "container:") {
			return "NetworkMode " + nm
		}
		if isGateNet(nm) {
			return "joins the gate network: " + nm
		}
		for _, opt := range hc.SecurityOpt {
			if reason := securityOptDeny(opt); reason != "" {
				return reason
			}
		}
		// NO host paths into siblings, period. Every bind is denied; a volume mount is
		// allowed only if it is a plain daemon-managed volume (no host `device` opt).
		if len(hc.Binds) > 0 {
			return "host bind mounts are disabled"
		}
		for _, m := range hc.Mounts {
			switch strings.ToLower(string(m.Type)) {
			case "bind":
				return "host bind mounts are disabled"
			case "volume":
				if isGateVol(m.Source) {
					return "mounts the gate socket volume: " + m.Source
				}
				if m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil {
					if dev := deviceOpt(m.VolumeOptions.DriverConfig.Options); dev != "" {
						return "host-bind volume mounts are disabled: " + dev
					}
				}
			}
		}
	}
	if c.NetworkingConfig != nil {
		for name := range c.NetworkingConfig.EndpointsConfig {
			if isGateNet(name) {
				return "attaches to the gate network: " + name
			}
		}
	}
	return ""
}

// deviceOpt returns the (host-bind) `device` driver option, matched case-insensitively
// because the daemon's local-volume driver lower-cases opt keys before reading them
// (so `Device`/`DEVICE` are honoured -- map keys are NOT folded by encoding/json, so we
// must fold them ourselves to match the daemon).
func deviceOpt(opts map[string]string) string {
	for k, v := range opts {
		if strings.ToLower(k) == "device" && v != "" {
			return v
		}
	}
	return ""
}

var defaultProfiles = map[string]bool{
	"default": true, "docker-default": true, "runtime/default": true, "builtin": true,
}

// securityOptDeny denies a single SecurityOpt entry, or returns "" if benign. A custom
// (non-default) seccomp/apparmor profile disables confinement as effectively as
// "unconfined" (an allow-all profile was a confirmed escape vector, cont.12).
func securityOptDeny(opt string) string {
	flat := strings.ToLower(strings.ReplaceAll(opt, " ", ""))
	if strings.Contains(flat, "unconfined") || strings.Contains(flat, "no-new-privileges:false") {
		return "weakens confinement: " + opt
	}
	if i := strings.Index(opt, "="); i >= 0 {
		key := strings.ToLower(strings.TrimSpace(opt[:i]))
		val := strings.ToLower(strings.TrimSpace(opt[i+1:]))
		if (key == "seccomp" || key == "apparmor") && !defaultProfiles[val] {
			return fmt.Sprintf("overrides the default %s profile (only the default is allowed): %s",
				key, truncate(opt, 60))
		}
	}
	return ""
}

func hasNoNewPriv(opts []string) bool {
	for _, o := range opts {
		if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(o, " ", "")), "no-new-privileges") {
			return true
		}
	}
	return false
}

// ---- exec / volume-create policy -------------------------------------------

// execBody: only Privileged matters (an exec must not out-privilege its container).
// A local one-field struct is enough -- the case-insensitive/Unicode-aware folding that
// matters comes from encoding/json itself, not from which struct we decode into.
type execBody struct {
	Privileged bool `json:"Privileged"`
}

// ---- gate-network / gate-volume helpers ------------------------------------

func isGateNet(name string) bool {
	// Under a unix upstream tecnativa is off all networks, so there is no gate network to
	// discover or police; the suffix pattern is a harmless backstop.
	return name != "" && gateNetRe.MatchString(name)
}

func isGateVol(name string) bool { return name != "" && gateVolRe.MatchString(name) }

func networkIsGate(string) bool {
	// No networked proxy exists under the unix-socket topology (cont.10), so no network
	// is the gate. (The TCP-fallback path is legacy and not exercised by this deployment.)
	return false
}

// ---- build network-mode gate (cont.9) --------------------------------------

func buildNetDeny(q url.Values) string {
	nm := q.Get("networkmode")
	if nm == "" {
		nm = q.Get("network")
	}
	low := strings.ToLower(nm)
	switch {
	case low == "host":
		return "build with host networking: a RUN step executes in the VM host netns (full create-policy bypass)"
	case strings.HasPrefix(low, "container:"):
		return "build sharing a container network namespace: " + nm
	case nm != "" && (isGateNet(nm) || networkIsGate(nm)):
		return "build joining the gate network: " + nm
	}
	return ""
}

// ---- ownership ------------------------------------------------------------

func targetIsOurs(id string) bool {
	resp, err := upstreamClient.Get("http://upstream/containers/" + url.PathEscape(id) + "/json")
	if err != nil {
		return false // fail closed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var data struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false
	}
	return data.Config.Labels[ownLabel] == "1"
}

// ---- HTTP handler ----------------------------------------------------------

func handler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path // already %xx-decoded by net/http -- same view the daemon routes on
	switch {
	case r.Method == http.MethodPost && createRe.MatchString(p):
		handleCreate(w, r)
	case r.Method == http.MethodPost && execRe.MatchString(p):
		handleExecCreate(w, r, execRe.FindStringSubmatch(p)[1])
	case attachRe.MatchString(p): // any method (POST /attach and GET /attach/ws) -- a hijack
		if !targetIsOurs(attachRe.FindStringSubmatch(p)[1]) {
			deny(w, "attach to a container we don't own")
			return
		}
		forwardMaybeUpgrade(w, r)
	case hijackRe.MatchString(p): // exec start, /session
		forwardMaybeUpgrade(w, r)
	case archiveRe.MatchString(p): // docker cp, read (GET) and write (PUT) -- streams, not an upgrade
		if !targetIsOurs(archiveRe.FindStringSubmatch(p)[1]) {
			deny(w, "archive (docker cp) a container we don't own")
			return
		}
		proxy.ServeHTTP(w, r)
	case r.Method == http.MethodPost && volCreateRe.MatchString(p):
		handleVolumeCreate(w, r)
	case r.Method == http.MethodPost && connectRe.MatchString(p):
		net := connectRe.FindStringSubmatch(p)[1]
		if isGateNet(net) || networkIsGate(net) {
			deny(w, "connect a container to the gate network: "+net)
			return
		}
		proxy.ServeHTTP(w, r)
	case r.Method == http.MethodPost && buildRe.MatchString(p):
		if reason := buildNetDeny(r.URL.Query()); reason != "" {
			deny(w, reason)
			return
		}
		log.Printf("ALLOW: build")
		proxy.ServeHTTP(w, r)
	default:
		// Everything else (start, ps, logs, inspect, pull, exec start, /session, ...)
		// streams straight through. tecnativa applies its coarse endpoint ACL.
		proxy.ServeHTTP(w, r)
	}
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		deny(w, "could not read create body")
		return
	}
	c, err := decodeCreate(body)
	if err != nil {
		deny(w, "unparseable create body")
		return
	}
	if reason := checkCreate(c); reason != "" {
		deny(w, reason)
		return
	}
	// Stamp ownership + force no-new-privileges (defense-in-depth; the dev container runs
	// with it). We re-marshal the parsed struct, so the daemon receives exactly the body
	// we inspected. NOTE: fields outside the daemon's own Config/HostConfig structs are
	// dropped here -- which is fail-SAFE (an unknown field can't be used to escalate) and
	// is fine for the workflow, which sets only Image/name/Cmd/network.
	if c.Config == nil {
		c.Config = &container.Config{}
	}
	if c.Config.Labels == nil {
		c.Config.Labels = map[string]string{}
	}
	c.Config.Labels[ownLabel] = "1"
	if c.HostConfig == nil {
		c.HostConfig = &container.HostConfig{}
	}
	if !hasNoNewPriv(c.HostConfig.SecurityOpt) {
		c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, "no-new-privileges:true")
	}
	out, err := json.Marshal(c)
	if err != nil {
		deny(w, "could not re-serialize create body")
		return
	}
	setBody(r, out)
	log.Printf("ALLOW: create (owned)")
	proxy.ServeHTTP(w, r)
}

func handleExecCreate(w http.ResponseWriter, r *http.Request, id string) {
	if !targetIsOurs(id) {
		deny(w, "exec into a container we don't own")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		deny(w, "could not read exec body")
		return
	}
	var e execBody
	if err := json.Unmarshal(body, &e); err != nil {
		deny(w, "unparseable exec body")
		return
	}
	if e.Privileged {
		deny(w, "privileged exec is disabled")
		return
	}
	// Forward the original bytes: the daemon parses them into the same Privileged bool we
	// just read, so there is no differential to launder.
	setBody(r, body)
	proxy.ServeHTTP(w, r)
}

func handleVolumeCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		deny(w, "could not read volume-create body")
		return
	}
	var v volume.CreateRequest
	if err := json.Unmarshal(body, &v); err != nil {
		deny(w, "unparseable volume-create body")
		return
	}
	if dev := deviceOpt(v.DriverOpts); dev != "" {
		deny(w, "host-bind volume creation is disabled: "+dev)
		return
	}
	setBody(r, body)
	log.Printf("ALLOW: volume create")
	proxy.ServeHTTP(w, r)
}

// forwardMaybeUpgrade sends a hijack-capable request (exec start, attach, /session) to
// the upstream: as a raw bidirectional tunnel if it carries a connection-upgrade, else as
// an ordinary proxied request (e.g. a detached exec start has no upgrade).
func forwardMaybeUpgrade(w http.ResponseWriter, r *http.Request) {
	if isUpgradeReq(r) {
		handleHijack(w, r)
		return
	}
	proxy.ServeHTTP(w, r)
}

func isUpgradeReq(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

// handleHijack tunnels a connection-upgrade request. We do this by hand rather than via
// ReverseProxy because ReverseProxy's upgrade copier returns on the FIRST direction's EOF
// and closes both conns -- which truncates a non-interactive `docker exec`'s stdout the
// moment the client half-closes its (empty) stdin. We instead half-close each side on its
// own EOF and wait for BOTH directions, so stdout/stderr fully drain (the Python relay's
// semantics). The request is written verbatim (Connection/Upgrade preserved) so the 101
// handshake survives.
//
// SMUGGLING GUARD (cont.8/cont.11, the test-escape `/session` case). We must read the
// upstream's RESPONSE before relaying any client bytes, and tunnel ONLY on a genuine
// 101 Switching Protocols. Otherwise no protocol switch happened, yet the client may have
// PIPELINED a second request (e.g. a privileged `POST /containers/create`) right behind the
// upgrade request -- those bytes are buffered in the hijacked clientBuf, and a blind relay
// would forward them straight to the daemon as the next keep-alive request, bypassing the
// ENTIRE create policy. On a non-101 response we relay the response through the normal
// ResponseWriter and return WITHOUT hijacking: net/http then re-parses any pipelined bytes
// as a fresh request that flows back through this handler (and gets policed/denied), and
// nothing reaches the daemon un-inspected.
func handleHijack(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		deny(w, "could not read upgrade request body")
		return
	}
	up, err := dialUpstream(r.Context(), "", "")
	if err != nil {
		deny(w, "upstream unreachable")
		return
	}
	defer up.Close()

	r.URL.RawPath = "" // forward the canonical decoded path
	var head bytes.Buffer
	fmt.Fprintf(&head, "%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI())
	host := r.Host
	if host == "" {
		host = "upstream"
	}
	fmt.Fprintf(&head, "Host: %s\r\n", host)
	fmt.Fprintf(&head, "Content-Length: %d\r\n", len(body))
	hdr := r.Header.Clone()
	hdr.Del("Content-Length") // we set our own; everything else (incl. Connection/Upgrade) verbatim
	_ = hdr.Write(&head)
	head.WriteString("\r\n")
	if _, err := up.Write(head.Bytes()); err != nil {
		deny(w, "upstream write failed")
		return
	}
	if _, err := up.Write(body); err != nil {
		deny(w, "upstream write failed")
		return
	}

	// Read the upstream response over a buffered reader. 1xx has no body (Go sets
	// resp.Body to NoBody for status < 200), so ReadResponse returns as soon as the
	// headers are in; any post-101 stream bytes stay buffered in upBuf for the tunnel.
	upBuf := bufio.NewReader(up)
	resp, err := http.ReadResponse(upBuf, r)
	if err != nil {
		deny(w, "upstream response read failed")
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// No upgrade -> NO raw relay. Relay the response and return; pipelined client
		// bytes are never forwarded to the upstream (the smuggling guard).
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// Genuine 101: take over the client connection and tunnel both directions raw.
	hj, ok := w.(http.Hijacker)
	if !ok {
		deny(w, "connection not hijackable")
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Replay the 101 status line + headers to the client so its upgrade handshake completes.
	var resphead bytes.Buffer
	fmt.Fprintf(&resphead, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	_ = resp.Header.Write(&resphead)
	resphead.WriteString("\r\n")
	if _, err := clientConn.Write(resphead.Bytes()); err != nil {
		return
	}

	// Tunnel. Copy FROM upBuf (not up): ReadResponse may have buffered post-header
	// stream bytes there. Half-close each side on its own EOF and wait for both, so a
	// non-interactive exec's stdout/stderr fully drain.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(up, clientBuf); halfCloseWrite(up) }()
	go func() { defer wg.Done(); io.Copy(clientConn, upBuf); halfCloseWrite(clientConn) }()
	wg.Wait()
}

func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close()
	}
}

// setBody replaces the (already-consumed) request body with exactly b and fixes the
// framing so the proxied request carries it with a correct Content-Length.
func setBody(r *http.Request, b []byte) {
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	r.TransferEncoding = nil
	r.Header.Del("Content-Length")
	r.Header.Del("Transfer-Encoding")
}

func deny(w http.ResponseWriter, msg string) {
	log.Printf("DENY: %s", msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "denied by authz shim: " + msg})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func main() {
	if upSock != "" {
		log.Printf("authz shim up (go) -> unix:%s | host mounts into siblings: DISABLED | tecnativa OFF all networks (no gate bridge to reach)", upSock)
	} else {
		log.Printf("authz shim up (go) -> %s:%s | host mounts into siblings: DISABLED", upHost, upPort)
	}
	srv := &http.Server{Addr: "0.0.0.0:2375", Handler: http.HandlerFunc(handler)}
	log.Fatal(srv.ListenAndServe())
}
