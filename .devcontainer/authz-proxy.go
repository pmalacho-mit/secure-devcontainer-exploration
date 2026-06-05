// authz-proxy.go
// Body-inspecting Docker gate, Go port of the former authz-proxy.py.
//
//	app  (DOCKER_HOST=unix:///run/app/docker.sock -- cont.20)
//	  -> this shim            (polices create/exec/volume-create/attach/cp/build by content;
//	     listens on a unix socket on the app-sock volume, OFF all networks -- cont.20)
//	    -> docker-endpoint-proxy  (tecnativa: coarse endpoint ACL, holds the real socket,
//	       reached over a unix socket; tecnativa is OFF all networks -- cont.10)
//	      -> /var/run/docker.sock
//
// CROSS-TENANT PIVOT (cont.20). The shim authorises the REQUEST, not the CALLER: a read is
// allowed if the TARGET is in our project ("same-project readable"). That is only safe if the
// shim is reachable by our project alone. While the shim listened on tcp://docker-authz:2375
// on the project's `_dev` bridge, a foreign tenant could `docker network connect <victim>_dev`
// a sibling, reach the VICTIM's shim, and have it export/inspect its own containers -- a
// confirmed cross-tenant read (another agent's home dir + Claude transcript). Fixed two ways:
// (a) the shim moves off the network onto a unix socket (no IP to pivot to -- the primary,
// caller-independent boundary), and (b) the shim refuses to place a sibling on, or inspect,
// any network owned by another Compose project (closes the pivot cooperatively + kills the
// IP-recon). Lifecycle verbs (stop/kill/rm/rename) are now owned-only too.
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
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// ---- config / upstream ------------------------------------------------------

// ownLabel keys the ownership stamp; projectLabel is Compose's own per-project label.
// The VALUE of ownLabel is per-project (ownerID), not a global "1" -- see discoverIdentity.
const (
	ownLabel     = "authz.owned"
	projectLabel = "com.docker.compose.project"
)

// ownerID stamps containers we create and is what targetIsOurs compares against; ourProject
// is this shim's Compose project, used to let the app inspect ITS OWN project's containers
// (self, tecnativa, the shim) without exposing sibling projects. Both are resolved at
// startup by discoverIdentity. Until then ownerID is "" so nothing is "ours" (fail closed).
var (
	ownerID    = ""
	ourProject = ""
)

// denyVols is an exact-name denylist of globally-shared, un-scoped daemon volumes a sibling
// must not get a writable handle to. The VS Code Dev Containers extension creates a single
// global `vscode` server-cache volume and mounts it into EVERY project's dev container at
// /vscode; it holds executable server code both containers run, so a root write into it is a
// cross-project code-execution foothold (assessment finding F2). Configurable via
// DENY_VOLUMES (comma-separated) so other shared system volumes can be added without a code
// change. A volume is referenced by EXACT name (the daemon resolves the literal string, no
// symlink/path dereference), so an exact-name denylist is sufficient and not bypassable by
// path tricks -- the bind/VolumesFrom backdoors to the same data are already denied wholesale.
var denyVols = parseDenyVols(envOr("DENY_VOLUMES", "vscode"))

func parseDenyVols(s string) map[string]bool {
	m := map[string]bool{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			m[v] = true
		}
	}
	return m
}

func isSharedSysVol(name string) bool { return name != "" && denyVols[name] }

// ---- sibling capability allowlist (assessment finding F2, made configurable) --------------
//
// The dev container runs cap_drop: ALL; a sibling left at Docker's default ~14-cap set would
// exceed it. cont.12 deliberately did NOT force-drop, because a real workload (e.g. the browser
// sandbox) may need one of the default caps. This resolves that tension: we force CapDrop:["ALL"]
// and re-add ONLY a configurable allowlist -- defaulting to the "mostly safe" caps real images
// commonly need (privilege-dropping entrypoints, chown, binding low ports, ping). Critically the
// allowlist is CLAMPED to Docker's default set at parse time, so this knob can tighten or pick a
// different subset, but can NEVER grant a cap beyond the defaults (SYS_ADMIN, NET_ADMIN, ... stay
// off -- those remain denied wholesale, same as CapAdd in the request body).

// dockerDefaultCaps is the hard ceiling: Docker's default capability bounding set (bare names,
// no CAP_ prefix). SIBLING_CAPS may select any subset of these and nothing else.
var dockerDefaultCaps = map[string]bool{
	"CHOWN": true, "DAC_OVERRIDE": true, "FSETID": true, "FOWNER": true,
	"MKNOD": true, "NET_RAW": true, "SETGID": true, "SETUID": true,
	"SETFCAP": true, "SETPCAP": true, "NET_BIND_SERVICE": true, "SYS_CHROOT": true,
	"KILL": true, "AUDIT_WRITE": true,
}

// defaultSiblingCaps is the "mostly safe" default allowlist: privilege-dropping (SETUID/SETGID),
// ownership/permission fixes in entrypoints (CHOWN/DAC_OVERRIDE/FOWNER), binding ports <1024
// (NET_BIND_SERVICE), and ping/raw sockets (NET_RAW). NOTE: a Chromium/Playwright setuid sandbox
// often also needs SYS_CHROOT -- if the browser workflow breaks, add it (or set SIBLING_CAPS=default).
const defaultSiblingCaps = "SETUID,SETGID,CHOWN,DAC_OVERRIDE,FOWNER,NET_BIND_SERVICE,NET_RAW"

// forceCapDrop/siblingCaps are resolved once from SIBLING_CAPS. forceCapDrop=false means "leave
// Docker's default set" (the cont.12 behaviour, opt-out); otherwise siblingCaps is the clamped
// CapAdd list injected alongside CapDrop:["ALL"].
var forceCapDrop, siblingCaps = parseSiblingCaps(envOr("SIBLING_CAPS", defaultSiblingCaps))

// parseSiblingCaps interprets the SIBLING_CAPS env value:
//   - "default"/"keep" -> (false, nil): do not inject; siblings keep Docker's default ~14 caps.
//   - "none"/""        -> (true, nil): CapDrop ALL and add nothing (parity with the dev container).
//   - else             -> (true, <clamped list>): CapDrop ALL, CapAdd only the listed caps that
//     are within dockerDefaultCaps. A cap OUTSIDE the defaults is rejected (logged + dropped),
//     so the knob can never escalate beyond the default set.
func parseSiblingCaps(s string) (bool, []string) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "default", "keep":
		return false, nil
	case "none", "":
		return true, nil
	}
	var caps []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(s, ",") {
		c := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "CAP_")
		if c == "" || seen[c] {
			continue
		}
		if !dockerDefaultCaps[c] {
			log.Printf("WARNING: SIBLING_CAPS: ignoring %q -- outside Docker's default capability set "+
				"(this knob cannot grant caps beyond the default ~14)", raw)
			continue
		}
		seen[c] = true
		caps = append(caps, c)
	}
	return true, caps
}

// applySiblingCaps force-drops every capability and re-adds only the configured (clamped)
// allowlist on a created sibling, so it never exceeds the bounded set. CapAdd in the request
// body is already denied by checkCreate, so this overwrite never honours attacker input.
func applySiblingCaps(hc *container.HostConfig) {
	if !forceCapDrop {
		return
	}
	hc.CapDrop = []string{"ALL"}
	hc.CapAdd = siblingCaps
}

var (
	// cont.10: reach tecnativa over a unix-domain socket on a shared volume. tecnativa
	// then runs `network_mode: none` (off ALL bridges), so no build/sibling netns has an
	// IP to route to. UPSTREAM_HOST/PORT remain as a TCP fallback (used by the DESIGN's
	// "throwaway shim chained in front of the running one" live-validation pattern).
	upSock = os.Getenv("UPSTREAM_SOCK")
	upHost = envOr("UPSTREAM_HOST", "docker-endpoint-proxy")
	upPort = envOr("UPSTREAM_PORT", "2375")

	// cont.20: the shim's OWN authz endpoint moves off the network. Previously it listened
	// on tcp://docker-authz:2375 on the project's `_dev` bridge -- a bridge ANY container on
	// the daemon can join (`docker network connect <victim>_dev`). Because the shim authorises
	// the REQUEST but not the CALLER ("same-project readable" trusts whoever can reach it), a
	// foreign tenant could pivot a sibling onto the victim's `_dev`, reach the VICTIM's shim,
	// and have it export/inspect its own (same-project) containers -- a confirmed cross-tenant
	// read. The fix mirrors what cont.10 did for tecnativa: listen on a unix socket on a
	// volume mounted ONLY into the dev container. A unix socket is a mount-namespace object,
	// unreachable from anything that only shares the network -- so there is no shim IP to pivot
	// to. LISTEN_ADDR remains a TCP fallback (the throwaway-shim live-validation pattern).
	listenSock = os.Getenv("LISTEN_SOCK")
	listenAddr = envOr("LISTEN_ADDR", "0.0.0.0:2375")

	// The gate network/volume name patterns (Compose project-prefixes them). Under a unix
	// upstream the gate network does not exist; the suffix check is a cheap, harmless
	// backstop and isGateVol still matters (the socket lives on the gate-sock volume).
	// (?i) -- assessment finding F11: the rest of the policy folds case, so these must too.
	// Docker resolves volume/network names case-SENSITIVELY (a `GATE-SOCK` is a different,
	// empty volume today), so this is a latent consistency fix rather than a live hole, but
	// it removes a case differential contrary to the "no case differentials" philosophy.
	gateNetRe = regexp.MustCompile(`(?i)(^|[-_])gate$`)
	gateVolRe = regexp.MustCompile(`(?i)(^|[-_])gate-sock$`)
	// cont.20: the new downstream control socket lives on the `app-sock` volume. A sibling
	// that mounted it would get a DIRECT handle to the shim's authz endpoint (full control
	// plane, no caller check) -- the gate-sock bypass reborn. Deny it exactly like gate-sock.
	// (The short `-v name:/path` form already lands in HostConfig.Binds, which is denied
	// wholesale; this covers the `--mount type=volume,source=app-sock` long form.)
	appSockRe = regexp.MustCompile(`(?i)(^|[-_])app-sock$`)

	// Routing patterns run against the DECODED path (r.URL.Path). The daemon also accepts
	// an optional /vX.Y API-version prefix, which we allow here too.
	createRe    = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/create$`)
	execRe      = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/exec$`)
	attachRe    = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/attach(?:/ws)?$`)
	archiveRe   = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/archive$`)
	connectRe   = regexp.MustCompile(`^/(?:v[0-9.]+/)?networks/([^/]+)/connect$`)
	// assessment finding F4: `docker network disconnect` (sever a container from a network).
	// Ungated, it let a sibling cut ANY container off ANY network (a persistent cross-tenant
	// DoS). Gate it by the same network-ownership check connect uses (id is capture group 1).
	disconnectRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?networks/([^/]+)/disconnect$`)
	// assessment finding F10: `docker network create`. Ungated, a sibling could create a
	// macvlan/ipvlan network with `parent=<host-iface>` -- L2 reach the dev container itself
	// lacks. Single segment, POST-only, so it never collides with the GET networkInspectRe
	// (also single-segment) or the two-segment connect/disconnect routes.
	netCreateRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?networks/create$`)
	// assessment finding F7: the `prune` endpoints are daemon-GLOBAL -- a single call deletes
	// EVERY project's stopped containers / unused volumes / dangling images / unused networks
	// / build cache. tecnativa allows them by endpoint category, so they streamed through.
	// Denied outright (pruning your own leftovers is an owned `rm`, which is already gated).
	pruneRe     = regexp.MustCompile(`^/(?:v[0-9.]+/)?(?:containers|volumes|images|networks|build)/prune$`)
	volCreateRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?volumes/create$`)
	buildRe     = regexp.MustCompile(`^/(?:v[0-9.]+/)?build$`)
	// Container READ endpoints that leak another container's filesystem / output / config:
	//   export  -> the entire container-layer fs as a tar  (assessment finding F1: this
	//              dumped a sibling project's home dir + the other agent's Claude transcript)
	//   logs    -> stdout/stderr   top -> process list   changes -> fs diff
	//   json    -> inspect (env, mounts, labels, config)
	// These were ungated (they streamed straight through to tecnativa, which filters by
	// endpoint only). Gate them by READABILITY: a container is readable if we own it OR it
	// is in our own Compose project (so the app can still inspect itself / its network /
	// tecnativa -- the workflow's `devcontainer.inspect()` needs this -- but cannot read a
	// sibling project's containers). The id is capture group 1.
	// assessment finding F7 (this round): `stats` was MISSING from this set, so a sibling's
	// live CPU/mem/net/block-IO metrics + full 64-char container ID streamed cross-project.
	// It is the same cross-tenant observability the read gate exists to deny -- add it.
	readRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/(?:export|logs|top|changes|json|stats)$`)
	// image export (`docker save`) leaks any image's layers cross-tenant; images carry no
	// ownership label, so this is denied outright (the workflow builds+runs images, never
	// `docker save`s them). imageGetRe matches the SINGULAR /images/{id}/get; assessment
	// finding F8: the real `docker save` CLI uses the PLURAL /images/get?names=... (no middle
	// segment), which imageGetRe (it requires `(.+)/get`) does not catch -- so it streamed
	// foreign layers. imagesExportRe closes the plural form.
	imageGetRe     = regexp.MustCompile(`^/(?:v[0-9.]+/)?images/(.+)/get$`)
	imagesExportRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?images/get$`)
	// cont.20: `GET /networks/{id}` (docker network inspect) leaked a FOREIGN project's
	// container IPs -- the recon step the cross-tenant pivot used to find the victim's shim
	// address. Gate it by project (own/built-in allowed, foreign denied). Matches a single
	// id segment only, so it never shadows `/networks` (list), `/networks/create` (POST), or
	// `/networks/{id}/connect` (a two-segment path handled separately).
	networkInspectRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?networks/([^/]+)$`)
	// cont.20: lifecycle/control verbs on a container. Attacker 3 showed a foreign-project
	// `rename` reaching the daemon -- cross-tenant integrity control (rename/stop/kill/rm).
	// Gate these by OWNERSHIP (you control only what you created), symmetric with exec/cp.
	// assessment finding F6: `start` was MISSING from this set, so a sibling could (re)start
	// any stopped container on the daemon -- now gated owned-only like the rest.
	ctrlRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)/(?:start|stop|kill|restart|pause|unpause|rename|update)$`)
	// `DELETE /containers/{id}` is `docker rm`. Single id segment (won't match /create, POST).
	rmRe = regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/([^/]+)$`)
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
		// CgroupnsMode was unchecked (assessment defense-in-depth gap 2): the other
		// namespace modes are all gated, cgroup ns was not, so `--cgroupns=host` was
		// accepted -- the dev container shares no namespace, a sibling must not either.
		// "private" (its own cgroup ns -- strictly MORE isolated) and "" (daemon default)
		// stay allowed; only host (or any non-private value) is denied.
		if cn := strings.ToLower(string(hc.CgroupnsMode)); cn != "" && cn != "private" {
			return "shares namespace: cgroupnsmode " + string(hc.CgroupnsMode)
		}
		// MaskedPaths/ReadonlyPaths were unchecked (assessment defense-in-depth gap 1).
		// When nil the daemon applies its hardened defaults (masking /proc/kcore, making
		// /proc/sysrq-trigger read-only, ...); a sibling that sets either field explicitly
		// (e.g. MaskedPaths:[] to UNMASK everything) gets a weaker /proc than the dev
		// container -- a writable /proc/sysrq-trigger is a VM-wide DoS primitive. The dev
		// container never overrides these, so reject any non-nil override (fail closed).
		if hc.MaskedPaths != nil {
			return "overrides MaskedPaths (the daemon's default /proc masking must stand)"
		}
		if hc.ReadonlyPaths != nil {
			return "overrides ReadonlyPaths (the daemon's default /proc read-only set must stand)"
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
				if isShimSockVol(m.Source) {
					return "mounts a shim socket volume (direct path to the gate/authz endpoint): " + m.Source
				}
				if isSharedSysVol(m.Source) {
					return "mounts a globally-shared system volume (cross-project read/write + code-exec foothold): " + m.Source
				}
				if m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil {
					if dev := deviceOpt(m.VolumeOptions.DriverConfig.Options); dev != "" {
						return "host-bind volume mounts are disabled: " + dev
					}
				}
			case "tmpfs":
				// in-memory, no host path -- the dev container uses tmpfs too. Allowed.
			default:
				// assessment finding F10 (this round): the switch inspected only bind/volume,
				// so `Type:"image"` (mounts an image rootfs) and any future mount type the
				// daemon adds fell through ALLOWED. Default-deny unknown types: a sibling may
				// only use the explicitly-vetted ones (volume/tmpfs). Empty type is rejected by
				// the daemon anyway; denying it here is fail-closed, not a regression.
				return "mount type not allowed: " + string(m.Type)
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
	if strings.Contains(flat, "unconfined") {
		return "weakens confinement: " + opt
	}
	// assessment finding F3: the daemon's parseSecurityOpt accepts BOTH `key=value` and the
	// deprecated `key:value` form. We only split on `=`, so `seccomp:{...allow-all...}` (a
	// colon-separated CUSTOM profile -- no "unconfined" substring to trip the flat check) sailed
	// past and re-opened the cont.12 confinement bypass. Split on whichever of `=`/`:` appears
	// FIRST, so the colon form is policed identically. (A `=`-form JSON value's inner `:` always
	// comes after the `seccomp=`/`apparmor=` `=`, so IndexAny still keys on the separator.)
	if i := strings.IndexAny(opt, "=:"); i >= 0 {
		key := strings.ToLower(strings.TrimSpace(opt[:i]))
		val := strings.ToLower(strings.TrimSpace(opt[i+1:]))
		if (key == "seccomp" || key == "apparmor") && !defaultProfiles[val] {
			return fmt.Sprintf("overrides the default %s profile (only the default is allowed): %s",
				key, truncate(opt, 60))
		}
		// assessment finding (this round): the daemon honours `no-new-privileges` with EITHER
		// separator, but the old check only matched the literal colon form `no-new-privileges:false`.
		// `--security-opt no-new-privileges=false` (equals form) therefore passed the deny AND --
		// because hasNoNewPriv prefix-matched the key -- suppressed the forced `:true`, so the
		// sibling ran with NoNewPrivs:0. Route the key through the same `=`/`:` split so both
		// separators are policed identically (the exact differential class the Go port exists to kill).
		if key == "no-new-privileges" && val == "false" {
			return "weakens confinement (no_new_privs disabled): " + opt
		}
	}
	return ""
}

// hasNoNewPriv reports whether the SecurityOpt list ALREADY enables no_new_privs, so handleCreate
// does not double-inject. It counts ONLY an explicit-true form (either separator, or the bare flag);
// a `=false`/`:false` value is rejected upstream by securityOptDeny, but matching only true here is
// the tamper-resistant invariant -- an unrecognized value can never masquerade as "already set".
func hasNoNewPriv(opts []string) bool {
	for _, o := range opts {
		flat := strings.ToLower(strings.ReplaceAll(o, " ", ""))
		if flat == "no-new-privileges" || flat == "no-new-privileges:true" || flat == "no-new-privileges=true" {
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

// isShimSockVol covers BOTH shim-socket volumes a sibling must never get a handle to: the
// upstream gate-sock (-> tecnativa) and the cont.20 downstream app-sock (-> this shim's
// authz endpoint). A handle to either is a full create-policy bypass.
func isShimSockVol(name string) bool {
	return name != "" && (gateVolRe.MatchString(name) || appSockRe.MatchString(name))
}

func networkIsGate(string) bool {
	// No networked proxy exists under the unix-socket topology (cont.10), so no network
	// is the gate. (The TCP-fallback path is legacy and not exercised by this deployment.)
	return false
}

// ---- cross-project network gate (cont.20) ----------------------------------

// inspectNetworkLabels fetches a network's labels from the upstream (NOT through handler).
// Fails closed (nil,false) on any error / non-200.
func inspectNetworkLabels(id string) (map[string]string, bool) {
	resp, err := upstreamClient.Get("http://upstream/networks/" + url.PathEscape(id))
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var data struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false
	}
	return data.Labels, true
}

// networkForeign reports whether a network belongs to a DIFFERENT Compose project than ours
// -- the precise condition that closes the pivot without over-blocking. A foreign `_dev`
// network always carries `com.docker.compose.project=<other>`; our own carries ours; built-in
// (bridge/none) and user-created networks carry no such label and stay allowed. Guarded on
// ourProject!="" so a discovery failure can't deny our OWN network; falls open on an inspect
// error (defence-in-depth behind the unix-socket move, which is the real boundary).
func networkForeign(id string) bool {
	if ourProject == "" {
		return false
	}
	labels, ok := inspectNetworkLabels(id)
	if !ok {
		return false
	}
	p := labels[projectLabel]
	return p != "" && p != ourProject
}

// isBuiltinNetMode is true for network modes that are not joinable foreign bridges: the
// daemon defaults and the namespace modes (host/container: are already denied in checkCreate).
func isBuiltinNetMode(nm string) bool {
	switch strings.ToLower(nm) {
	case "", "default", "bridge", "none", "host":
		return true
	}
	return strings.HasPrefix(strings.ToLower(nm), "container:")
}

// createNetworkRefs lists the named networks a create attaches to (primary NetworkMode plus
// any NetworkingConfig endpoints), skipping built-ins -- the candidates for the foreign-net
// check in handleCreate.
func createNetworkRefs(c *createBody) []string {
	var refs []string
	if c.HostConfig != nil {
		if nm := string(c.HostConfig.NetworkMode); nm != "" && !isBuiltinNetMode(nm) {
			refs = append(refs, nm)
		}
	}
	if c.NetworkingConfig != nil {
		for name := range c.NetworkingConfig.EndpointsConfig {
			refs = append(refs, name)
		}
	}
	return refs
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

// inspectLabels fetches a target's Config.Labels straight from the upstream (NOT through
// handler, so no recursion). Fails closed (nil,false) on any error / non-200.
func inspectLabels(id string) (map[string]string, bool) {
	resp, err := upstreamClient.Get("http://upstream/containers/" + url.PathEscape(id) + "/json")
	if err != nil {
		return nil, false // fail closed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var data struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false
	}
	return data.Config.Labels, true
}

// labelIsOurs / labelReadable are the pure ownership predicates (hermetically testable).
//
//   - OURS = stamped with THIS shim's ownerID. Gates write/control (exec, attach, docker cp).
//     ownerID is per-project (assessment cross-tenant gap 3 / cross-tenant finding): the old
//     global `authz.owned=1` meant any sibling created by ANY project's shim was "owned" by
//     every shim, so two dev containers could exec/cp into each other's created siblings.
//   - READABLE = ours, OR in our own Compose project. Gates the read endpoints (export, logs,
//     top, changes, inspect). Same-project is needed so the app can inspect itself / its dev
//     network / tecnativa (the workflow does this) while a SIBLING project's containers -- a
//     different Compose project, and not owned -- stay unreadable.
func labelIsOurs(labels map[string]string) bool {
	return ownerID != "" && labels[ownLabel] == ownerID
}

func labelReadable(labels map[string]string) bool {
	if labelIsOurs(labels) {
		return true
	}
	return ourProject != "" && labels[projectLabel] == ourProject
}

func targetIsOurs(id string) bool {
	labels, ok := inspectLabels(id)
	return ok && labelIsOurs(labels)
}

func targetReadable(id string) bool {
	labels, ok := inspectLabels(id)
	return ok && labelReadable(labels)
}

// discoverIdentity resolves this shim's ownerID + ourProject at startup. We inspect our OWN
// container (hostname == container id by default) for its Compose project label and derive a
// PROJECT-SCOPED ownerID from it, so created siblings are owned only by this project's shim.
// Fallbacks keep ownerID unique-per-shim (never the old global constant) so a discovery
// failure can never make us share ownership with a sibling project -- it only fails closed
// (we lose same-project reads, and after a restart lose our own old siblings), never open.
func discoverIdentity() {
	host, err := os.Hostname()
	if err != nil || host == "" {
		log.Printf("WARNING: cannot read own hostname; ownership disabled (fail closed): %v", err)
		return
	}
	for i := 0; i < 20; i++ { // retry ~10s while the upstream comes up
		labels, ok := inspectLabels(host)
		if ok {
			if p := labels[projectLabel]; p != "" {
				ourProject = p
				ownerID = "project:" + p
				log.Printf("identity: ownerID=%q project=%q (self=%s)", ownerID, ourProject, host)
				return
			}
			// Self resolved but carries no Compose label: still pick a unique owner so
			// created siblings are owned, but leave ourProject empty (same-project reads off).
			ownerID = "host:" + host
			log.Printf("WARNING: self %s has no %s label; ownerID=%q, cross-project reads disabled", host, projectLabel, ownerID)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	ownerID = "host:" + host
	log.Printf("WARNING: could not inspect self %s after retries; ownerID=%q (created siblings still owned; same-project reads disabled)", host, ownerID)
}

// ---- HTTP handler ----------------------------------------------------------

func handler(w http.ResponseWriter, r *http.Request) {
	// r.URL.Path is already %xx-decoded by net/http (the view the daemon routes on -- the
	// Finding M invariant). We additionally route on its CLEANED form: path.Clean collapses
	// `//`, `/./` and `/../` so a non-canonical path that RESOLVES to a gated endpoint (e.g.
	// `//containers/create`, `/foo/../containers/create`) is policed exactly like the canonical
	// one. Previously the gate survived such paths only because moby happens to 301 them
	// instead of executing -- an upstream implementation detail (assessment recommendation 1).
	// Routing on the cleaned path closes that whole class regardless of daemon behaviour.
	p := path.Clean(r.URL.Path)
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
		handleNetworkAttach(w, r, connectRe.FindStringSubmatch(p)[1], "connect")
	case r.Method == http.MethodPost && disconnectRe.MatchString(p): // F4: symmetric with connect
		handleNetworkAttach(w, r, disconnectRe.FindStringSubmatch(p)[1], "disconnect")
	case r.Method == http.MethodPost && netCreateRe.MatchString(p): // F10
		handleNetworkCreate(w, r)
	case r.Method == http.MethodPost && pruneRe.MatchString(p): // F7: daemon-global, denied outright
		deny(w, "prune is disabled: it is daemon-global and would delete other projects' resources")
	case r.Method == http.MethodGet && networkInspectRe.MatchString(p):
		id := networkInspectRe.FindStringSubmatch(p)[1]
		if networkForeign(id) { // cont.20: don't leak a foreign project's container IPs
			deny(w, "inspect a network owned by another project: "+id)
			return
		}
		proxy.ServeHTTP(w, r)
	case r.Method == http.MethodPost && ctrlRe.MatchString(p):
		id := ctrlRe.FindStringSubmatch(p)[1]
		if !targetIsOurs(id) { // cont.20: control only containers we created
			deny(w, "control (stop/kill/restart/rename/...) a container we don't own")
			return
		}
		proxy.ServeHTTP(w, r)
	case r.Method == http.MethodDelete && rmRe.MatchString(p):
		id := rmRe.FindStringSubmatch(p)[1]
		if !targetIsOurs(id) { // cont.20: remove only containers we created
			deny(w, "remove (docker rm) a container we don't own")
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
	case r.Method == http.MethodGet && (imageGetRe.MatchString(p) || imagesExportRe.MatchString(p)):
		deny(w, "image export (docker save) is disabled: leaks image layers cross-tenant")
	case r.Method == http.MethodGet && readRe.MatchString(p):
		id := readRe.FindStringSubmatch(p)[1]
		if !targetReadable(id) {
			deny(w, "read (export/logs/top/changes/inspect) of a container outside our project")
			return
		}
		proxy.ServeHTTP(w, r)
	default:
		// Everything else (ps, version, pull, image inspect, ...) streams straight through.
		// (start/stop/... and exec start/`/session` are gated above; tecnativa applies its
		// coarse endpoint ACL to whatever remains.)
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
	// cont.20: a create may not place the sibling on another project's network (the pivot
	// onto a victim's `_dev` bridge). checkCreate is pure (hermetically tested); the network
	// project lookup needs the upstream, so it lives here in the handler.
	for _, ref := range createNetworkRefs(c) {
		if networkForeign(ref) {
			deny(w, "create on a network owned by another project: "+ref)
			return
		}
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
	c.Config.Labels[ownLabel] = ownerID // per-project owner, not a global "1" (cross-tenant fix)
	if c.HostConfig == nil {
		c.HostConfig = &container.HostConfig{}
	}
	if !hasNoNewPriv(c.HostConfig.SecurityOpt) {
		c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, "no-new-privileges:true")
	}
	// F2: force CapDrop:["ALL"] + a bounded CapAdd allowlist (SIBLING_CAPS), so a sibling never
	// carries more than the configured "mostly safe" caps (and never more than Docker's defaults).
	applySiblingCaps(c.HostConfig)
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

// netCreateBody is a local minimal view of POST /networks/create: Driver is a struct field
// (encoding/json folds it like the daemon), Options is the driver-option map (NOT folded by
// encoding/json, so networkCreateDeny lower-cases the key itself -- mirroring how the daemon
// reads the `parent` option key).
type netCreateBody struct {
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
}

// networkCreateDeny denies a network create that would exceed the dev container's own reach
// (assessment finding F10): macvlan/ipvlan attach a host parent NIC (L2 the dev container
// lacks), and any `parent` driver option pins a host interface. Siblings never legitimately
// create such networks. Fails closed on an unparseable body.
func networkCreateDeny(body []byte) string {
	var nc netCreateBody
	if err := json.Unmarshal(body, &nc); err != nil {
		return "unparseable network-create body"
	}
	switch strings.ToLower(nc.Driver) {
	case "macvlan", "ipvlan":
		return "macvlan/ipvlan networks are disabled (a host parent interface exceeds the dev container's reach)"
	}
	for k := range nc.Options {
		if strings.ToLower(k) == "parent" {
			return "network with a host parent interface is disabled"
		}
	}
	return ""
}

func handleNetworkCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		deny(w, "could not read network-create body")
		return
	}
	if reason := networkCreateDeny(body); reason != "" {
		deny(w, reason)
		return
	}
	setBody(r, body)
	log.Printf("ALLOW: network create")
	proxy.ServeHTTP(w, r)
}

// networkAttachBody is the (case-folded by encoding/json, like the daemon) view of a
// connect/disconnect request -- we only need the target container reference.
type networkAttachBody struct {
	Container string `json:"Container"`
}

// handleNetworkAttach gates POST /networks/{id}/connect and .../disconnect on BOTH the
// network's owner AND the container's owner.
//
// assessment finding F5 (this round): the gate checked only the NETWORK (networkForeign),
// never the CONTAINER. `connect` is asymmetric -- it names the container to pull onto the
// network in the BODY -- so a tenant could connect a FOREIGN container onto its OWN (or a
// built-in) network, gaining cross-tenant L2 adjacency / MITM positioning, and symmetrically
// `disconnect` a foreign container from a network. Ownership-check the Container field with
// targetIsOurs, symmetric with exec/cp/stop: you may only (dis)connect containers you created.
func handleNetworkAttach(w http.ResponseWriter, r *http.Request, netID, verb string) {
	if isGateNet(netID) || networkIsGate(netID) {
		deny(w, verb+" the gate network: "+netID)
		return
	}
	if networkForeign(netID) { // cont.20: not another project's bridge
		deny(w, verb+" a network owned by another project: "+netID)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		deny(w, "could not read network-"+verb+" body")
		return
	}
	var nb networkAttachBody
	if err := json.Unmarshal(body, &nb); err != nil {
		deny(w, "unparseable network-"+verb+" body")
		return
	}
	if !targetIsOurs(nb.Container) { // F5: only (dis)connect containers we created
		deny(w, verb+" a container we don't own: "+nb.Container)
		return
	}
	setBody(r, body)
	log.Printf("ALLOW: network %s (owned container)", verb)
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
	discoverIdentity() // resolve ownerID + ourProject before serving (ownership fails closed until then)
	if upSock != "" {
		log.Printf("authz shim up (go) -> unix:%s | host mounts into siblings: DISABLED | tecnativa OFF all networks (no gate bridge to reach)", upSock)
	} else {
		log.Printf("authz shim up (go) -> %s:%s | host mounts into siblings: DISABLED", upHost, upPort)
	}
	if forceCapDrop {
		log.Printf("sibling caps: CapDrop=ALL, CapAdd=%v (SIBLING_CAPS; clamped to Docker's default set)", siblingCaps)
	} else {
		log.Printf("sibling caps: Docker default (SIBLING_CAPS=default -- not force-dropped)")
	}
	srv := &http.Server{Handler: http.HandlerFunc(handler)}
	// cont.20: listen on a unix socket on the app-sock volume (the dev container's ONLY route
	// to Docker), not a TCP port on the joinable `_dev` bridge. No shim IP => no cross-tenant
	// pivot target. LISTEN_SOCK unset falls back to TCP (the throwaway-shim test pattern).
	if listenSock != "" {
		_ = os.Remove(listenSock) // clear any stale socket from a previous run
		ln, err := net.Listen("unix", listenSock)
		if err != nil {
			log.Fatalf("listen unix %s: %v", listenSock, err)
		}
		// The dev container runs as non-root `vscode`; the shim runs as root, so the socket
		// is root-owned. 0660 wouldn't match the app's uid/gid; 0666 lets the dev user connect.
		// The app-sock volume is private to app+shim and is NOT a network object, so a
		// world-rw mode there grants nothing to anything off the volume (and a sibling can't
		// mount the volume at all -- isShimSockVol). Siblings never get this handle.
		if err := os.Chmod(listenSock, 0o666); err != nil {
			log.Printf("WARNING: chmod %s: %v (dev container may not be able to connect)", listenSock, err)
		}
		log.Printf("authz shim listening on unix:%s (off all networks)", listenSock)
		log.Fatal(srv.Serve(ln))
	}
	log.Printf("authz shim listening on tcp:%s (LISTEN_SOCK unset -- legacy/test path)", listenAddr)
	srv.Addr = listenAddr
	log.Fatal(srv.ListenAndServe())
}
