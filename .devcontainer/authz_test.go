package main

// Hermetic unit tests for the shim's pure policy logic (no Docker daemon needed) --
// the Go replacement for test_policy.py. Daemon-dependent paths (ownership of
// exec/attach/cp, build named-net resolution) are exercised by test-escape.sh against a
// live stack instead.
//
// The cont.14/15 "key case-confusion" and "Unicode case-fold" cases live here too, but
// note their MEANING changed: in Python they tested a bespoke canon_keys/has_nonascii_key
// defense; here they assert the differential is handled BY CONSTRUCTION -- we feed raw
// JSON with `binds` / `BINDS` / `Bindſ` and confirm Go's encoding/json folds them into
// HostConfig.Binds so the ordinary bind check fires. No special-casing required.

import (
	"encoding/json"
	"net/url"
	"path"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
)

// createDenied mirrors handleCreate's decision: unparseable -> deny, else checkCreate.
func createDenied(t *testing.T, body string) bool {
	t.Helper()
	c, err := decodeCreate([]byte(body))
	if err != nil {
		return true
	}
	return checkCreate(c) != ""
}

func wantCreate(t *testing.T, desc, body string, deny bool) {
	t.Helper()
	if got := createDenied(t, body); got != deny {
		t.Errorf("create %q: got denied=%v, want %v", desc, got, deny)
	}
}

func TestCreatePrivilegeNamespaceNetworkConfinement(t *testing.T) {
	const DENY, ALLOW = true, false
	wantCreate(t, "privileged", `{"HostConfig":{"Privileged":true}}`, DENY)
	wantCreate(t, "cap add", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, DENY)
	wantCreate(t, "devices", `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`, DENY)
	wantCreate(t, "device requests", `{"HostConfig":{"DeviceRequests":[{"Count":-1}]}}`, DENY)
	wantCreate(t, "device cgroup rules", `{"HostConfig":{"DeviceCgroupRules":["c 1:1 rwm"]}}`, DENY)
	wantCreate(t, "VolumesFrom", `{"HostConfig":{"VolumesFrom":["other"]}}`, DENY)
	wantCreate(t, "PidMode host", `{"HostConfig":{"PidMode":"host"}}`, DENY)
	wantCreate(t, "IpcMode host", `{"HostConfig":{"IpcMode":"host"}}`, DENY)
	wantCreate(t, "UTSMode host", `{"HostConfig":{"UTSMode":"host"}}`, DENY)
	wantCreate(t, "UsernsMode host", `{"HostConfig":{"UsernsMode":"host"}}`, DENY)
	wantCreate(t, "NetworkMode host", `{"HostConfig":{"NetworkMode":"host"}}`, DENY)
	wantCreate(t, "NetworkMode container", `{"HostConfig":{"NetworkMode":"container:abc123"}}`, DENY)
	wantCreate(t, "NetworkMode gate suffix", `{"HostConfig":{"NetworkMode":"myproj_gate"}}`, DENY)
	wantCreate(t, "EndpointsConfig gate", `{"NetworkingConfig":{"EndpointsConfig":{"myproj_gate":{}}}}`, DENY)
	wantCreate(t, "seccomp unconfined", `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, DENY)
	wantCreate(t, "apparmor unconfined", `{"HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`, DENY)
	wantCreate(t, "nnp false", `{"HostConfig":{"SecurityOpt":["no-new-privileges:false"]}}`, DENY)
	wantCreate(t, "seccomp allow-all JSON", `{"HostConfig":{"SecurityOpt":["seccomp={\"defaultAction\":\"SCMP_ACT_ALLOW\"}"]}}`, DENY)
	wantCreate(t, "apparmor custom profile", `{"HostConfig":{"SecurityOpt":["apparmor=my-profile"]}}`, DENY)
	wantCreate(t, "seccomp=default allowed", `{"Image":"x","HostConfig":{"SecurityOpt":["seccomp=default"]}}`, ALLOW)
	wantCreate(t, "apparmor=docker-default ok", `{"Image":"x","HostConfig":{"SecurityOpt":["apparmor=docker-default"]}}`, ALLOW)
	wantCreate(t, "seccomp=runtime/default ok", `{"Image":"x","HostConfig":{"SecurityOpt":["seccomp=runtime/default"]}}`, ALLOW)
	wantCreate(t, "label securityopt allowed", `{"Image":"x","HostConfig":{"SecurityOpt":["label=level:s0"]}}`, ALLOW)
	wantCreate(t, "unparseable body", `not json`, DENY)
}

func TestCreateNoHostMounts(t *testing.T) {
	const DENY, ALLOW = true, false
	wantCreate(t, "bind /etc", `{"HostConfig":{"Binds":["/etc:/etc"]}}`, DENY)
	wantCreate(t, "bind workspace-ish", `{"HostConfig":{"Binds":["/anything/workspace:/w"]}}`, DENY)
	wantCreate(t, "bind :ro", `{"HostConfig":{"Binds":["/data:/d:ro"]}}`, DENY)
	wantCreate(t, "mount type=bind", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/etc"}]}}`, DENY)
	inline := func(dev string) string {
		return `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/host","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"` + dev + `"}}}}]}}`
	}
	wantCreate(t, "inline vol device=/", inline("/"), DENY)
	wantCreate(t, "inline vol device=/etc", inline("/etc"), DENY)
	// still allowed -- nothing touching the host filesystem
	wantCreate(t, "plain peer on dev net", `{"Image":"x","HostConfig":{"NetworkMode":"myproj_dev","AutoRemove":true}}`, ALLOW)
	wantCreate(t, "no HostConfig", `{"Image":"x"}`, ALLOW)
	wantCreate(t, "plain named volume", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"data","Target":"/d"}]}}`, ALLOW)
	wantCreate(t, "anonymous volume", `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/d"}]}}`, ALLOW)
	wantCreate(t, "tmpfs mount", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/t"}]}}`, ALLOW)
}

func TestCreateGateSocketVolume(t *testing.T) {
	const DENY, ALLOW = true, false
	wantCreate(t, "mount gate-sock (--mount type=volume)", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"proj_gate-sock","Target":"/g"}]}}`, DENY)
	wantCreate(t, "mount gate-sock (bare name)", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"gate-sock","Target":"/g"}]}}`, DENY)
	wantCreate(t, "plain named volume allowed", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"myvol","Target":"/d"}]}}`, ALLOW)
	wantCreate(t, "gate-sock via -v (Bind) denied", `{"HostConfig":{"Binds":["proj_gate-sock:/g"]}}`, DENY)
}

// The differential class, now closed BY CONSTRUCTION: re-cased and Unicode-folded keys
// land in the same struct fields the daemon uses, so the ordinary checks catch them.
func TestCreateParserDifferentialClosedByConstruction(t *testing.T) {
	const DENY, ALLOW = true, false
	wantCreate(t, "lower-case binds", `{"Image":"x","HostConfig":{"binds":["/:/h"]}}`, DENY)
	wantCreate(t, "UPPER-CASE BINDS", `{"Image":"x","HostConfig":{"BINDS":["/:/h"]}}`, DENY)
	wantCreate(t, "lower-case hostconfig wrap", `{"Image":"x","hostconfig":{"Privileged":true}}`, DENY)
	wantCreate(t, "mixed HostConfig+privileged", `{"Image":"x","HostConfig":{"privileged":true}}`, DENY)
	wantCreate(t, "re-cased pidmode", `{"Image":"x","HostConfig":{"pidmode":"host"}}`, DENY)
	wantCreate(t, "re-cased networkmode host", `{"Image":"x","HostConfig":{"networkmode":"host"}}`, DENY)
	wantCreate(t, "re-cased mount Type=Bind", `{"HostConfig":{"Mounts":[{"Type":"Bind","Source":"/etc","Target":"/x"}]}}`, DENY)
	// cont.15: Go's encoding/json folds LONG-S 'ſ'(U+017F) and KELVIN 'K'(U+212A) to s/k
	// via the SAME bytes.EqualFold the daemon uses, so these land in Binds/NetworkMode.
	wantCreate(t, "long-s Bindſ", `{"Image":"x","HostConfig":{"Bindſ":["/:/h"]}}`, DENY)
	wantCreate(t, "kelvin in NetworKMode", `{"Image":"x","HostConfig":{"NetworKMode":"host"}}`, DENY)
	// re-cased inline volume device opt (map key folded by deviceOpt, mirroring the daemon)
	wantCreate(t, "re-cased inline Device opt", `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/h","VolumeOptions":{"DriverConfig":{"Options":{"o":"bind","Device":"/"}}}}]}}`, DENY)
	// benign all-lower-case create (Go clients may send any case) must STILL pass
	wantCreate(t, "benign all-lower create", `{"image":"x","hostconfig":{"networkmode":"myproj_dev"}}`, ALLOW)
	// ASCII keys with a non-ASCII VALUE are fine -- only the daemon's struct-field keys matter
	wantCreate(t, "non-ASCII value allowed", `{"Image":"x","Labels":{"team":"café"}}`, ALLOW)
}

// Defense-in-depth fields that were honoured by the daemon but unchecked by checkCreate
// (assessment gaps 1 & 2): MaskedPaths/ReadonlyPaths overrides and a host cgroup namespace.
func TestCreateCgroupnsMaskedReadonlyPaths(t *testing.T) {
	const DENY, ALLOW = true, false
	// cgroupns: host (or any non-private value) shares a namespace -> denied; private/absent ok.
	wantCreate(t, "cgroupns host", `{"HostConfig":{"CgroupnsMode":"host"}}`, DENY)
	wantCreate(t, "cgroupns HOST (case)", `{"Image":"x","HostConfig":{"CgroupnsMode":"HOST"}}`, DENY)
	wantCreate(t, "cgroupns private allowed", `{"Image":"x","HostConfig":{"CgroupnsMode":"private"}}`, ALLOW)
	wantCreate(t, "cgroupns absent allowed", `{"Image":"x","HostConfig":{}}`, ALLOW)
	// MaskedPaths/ReadonlyPaths: any explicit override (even []) is denied; absent (nil) is ok.
	wantCreate(t, "MaskedPaths emptied (unmask all)", `{"HostConfig":{"MaskedPaths":[]}}`, DENY)
	wantCreate(t, "MaskedPaths narrowed", `{"HostConfig":{"MaskedPaths":["/proc/kcore"]}}`, DENY)
	wantCreate(t, "ReadonlyPaths emptied", `{"HostConfig":{"ReadonlyPaths":[]}}`, DENY)
	wantCreate(t, "ReadonlyPaths set", `{"HostConfig":{"ReadonlyPaths":["/proc/bus"]}}`, DENY)
	wantCreate(t, "neither set allowed", `{"Image":"x","HostConfig":{"AutoRemove":true}}`, ALLOW)
	// re-cased keys still land in the same struct fields (parser-differential closed by construction)
	wantCreate(t, "re-cased cgroupnsmode host", `{"Image":"x","HostConfig":{"cgroupnsmode":"host"}}`, DENY)
	wantCreate(t, "re-cased maskedpaths", `{"HostConfig":{"maskedpaths":[]}}`, DENY)
}

// A globally-shared system volume (the VS Code `vscode` server-cache volume) must not be
// mountable into a sibling (assessment finding F2) -- it is a cross-project read/write +
// code-execution channel. Plain named volumes stay allowed.
func TestCreateSharedSystemVolume(t *testing.T) {
	const DENY, ALLOW = true, false
	wantCreate(t, "mount vscode (--mount type=volume)", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vscode","Target":"/sv"}]}}`, DENY)
	wantCreate(t, "vscode via -v (Bind) denied as a bind", `{"HostConfig":{"Binds":["vscode:/sv"]}}`, DENY)
	wantCreate(t, "plain named volume still allowed", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"myvol","Target":"/d"}]}}`, ALLOW)
	// isSharedSysVol is exact-name; a different name is not caught.
	if isSharedSysVol("vscode-other") || isSharedSysVol("") {
		t.Errorf("isSharedSysVol matched too broadly")
	}
	if !isSharedSysVol("vscode") {
		t.Errorf("isSharedSysVol should match the exact shared volume name")
	}
}

// Per-project ownership (assessment cross-tenant gap 3): a sibling stamped by THIS shim is
// ours; the old global `authz.owned=1` is not (a sibling project's stamp). Readability also
// accepts same-Compose-project containers (so the app can inspect itself), but never a
// sibling project's.
func TestOwnershipPredicates(t *testing.T) {
	defer func(o, p string) { ownerID, ourProject = o, p }(ownerID, ourProject)
	ownerID, ourProject = "project:alpha", "alpha"

	ours := map[string]string{ownLabel: "project:alpha"}
	siblingOwned := map[string]string{ownLabel: "project:beta"}
	legacyGlobal := map[string]string{ownLabel: "1"}
	sameProject := map[string]string{projectLabel: "alpha"}
	siblingProject := map[string]string{projectLabel: "beta"}
	unlabelled := map[string]string{}

	if !labelIsOurs(ours) {
		t.Error("our own stamp should be ours")
	}
	for _, m := range []map[string]string{siblingOwned, legacyGlobal, sameProject, siblingProject, unlabelled} {
		if labelIsOurs(m) {
			t.Errorf("labelIsOurs wrongly true for %v", m)
		}
	}
	for _, m := range []map[string]string{ours, sameProject} {
		if !labelReadable(m) {
			t.Errorf("labelReadable should be true for %v", m)
		}
	}
	for _, m := range []map[string]string{siblingOwned, legacyGlobal, siblingProject, unlabelled} {
		if labelReadable(m) {
			t.Errorf("labelReadable wrongly true for %v (cross-tenant leak)", m)
		}
	}
	// Fail closed: an empty ownerID owns nothing (the pre-discovery state).
	ownerID = ""
	if labelIsOurs(ours) {
		t.Error("empty ownerID must own nothing (fail closed)")
	}
}

// F2 (configurable): siblings get CapDrop:["ALL"] + a clamped allowlist. The clamp is the
// security property -- SIBLING_CAPS can pick any subset of Docker's default caps but can NEVER
// grant one beyond them.
func TestSiblingCapPolicy(t *testing.T) {
	asSet := func(caps []string) map[string]bool {
		m := map[string]bool{}
		for _, c := range caps {
			m[c] = true
		}
		return m
	}

	// default = the mostly-safe 7, force-on
	force, caps := parseSiblingCaps(defaultSiblingCaps)
	if !force {
		t.Fatal("default policy must force CapDrop")
	}
	got := asSet(caps)
	for _, want := range []string{"SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE", "NET_RAW"} {
		if !got[want] {
			t.Errorf("default allowlist missing %q", want)
		}
	}
	if len(caps) != 7 {
		t.Errorf("default allowlist size = %d, want 7 (%v)", len(caps), caps)
	}

	// the clamp: dangerous / non-default caps are dropped; only in-default ones survive
	force, caps = parseSiblingCaps("SYS_ADMIN,SETUID,cap_net_admin,SYS_PTRACE,CAP_FOWNER")
	got = asSet(caps)
	if !force || !got["SETUID"] || !got["FOWNER"] {
		t.Errorf("clamp dropped in-default caps (%v)", caps)
	}
	for _, bad := range []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"} {
		if got[bad] {
			t.Errorf("clamp let a non-default cap through: %q", bad)
		}
	}

	// can NEVER exceed the defaults: an all-dangerous list yields an empty allowlist
	if _, caps = parseSiblingCaps("SYS_ADMIN,NET_ADMIN,SYS_PTRACE,MAC_ADMIN,BPF"); len(caps) != 0 {
		t.Errorf("non-default caps must all be clamped away, got %v", caps)
	}

	// CAP_ prefix + case + dedup are normalized
	_, caps = parseSiblingCaps("cap_setuid, SetUid ,KILL")
	if got = asSet(caps); !got["SETUID"] || !got["KILL"] || len(caps) != 2 {
		t.Errorf("prefix/case/dedup normalization wrong: %v", caps)
	}

	// "default"/"keep" = do NOT force-drop (opt-out -> Docker's default set)
	for _, s := range []string{"default", "keep", "Default"} {
		if force, _ = parseSiblingCaps(s); force {
			t.Errorf("SIBLING_CAPS=%q must NOT force CapDrop", s)
		}
	}
	// "none"/"" = force-drop, add nothing
	for _, s := range []string{"none", "", "  "} {
		if force, caps = parseSiblingCaps(s); !force || len(caps) != 0 {
			t.Errorf("SIBLING_CAPS=%q must force-drop with empty CapAdd (force=%v caps=%v)", s, force, caps)
		}
	}

	// applySiblingCaps injects CapDrop:["ALL"] + the configured allowlist
	defer func(f bool, c []string) { forceCapDrop, siblingCaps = f, c }(forceCapDrop, siblingCaps)
	forceCapDrop, siblingCaps = true, []string{"SETUID", "CHOWN"}
	hc := &container.HostConfig{}
	applySiblingCaps(hc)
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("applySiblingCaps did not force CapDrop=ALL (got %v)", hc.CapDrop)
	}
	if g := asSet(hc.CapAdd); !g["SETUID"] || !g["CHOWN"] || len(hc.CapAdd) != 2 {
		t.Errorf("applySiblingCaps CapAdd wrong (got %v)", hc.CapAdd)
	}
	// opt-out leaves the HostConfig untouched
	forceCapDrop = false
	hc2 := &container.HostConfig{CapAdd: []string{"NET_RAW"}}
	applySiblingCaps(hc2)
	if len(hc2.CapDrop) != 0 || len(hc2.CapAdd) != 1 {
		t.Errorf("opt-out must not modify caps (drop=%v add=%v)", hc2.CapDrop, hc2.CapAdd)
	}
}

func TestExecPolicy(t *testing.T) {
	denied := func(body string) bool {
		var e execBody
		if err := json.Unmarshal([]byte(body), &e); err != nil {
			return true
		}
		return e.Privileged
	}
	cases := []struct {
		body string
		deny bool
	}{
		{`{"Privileged":true,"Cmd":["sh"]}`, true},
		{`{"Privileged":true}`, true},
		{`{"Cmd":["sh"],"AttachStdout":true}`, false},
		{`{"Cmd":["id"],"User":"root"}`, false},
		{`not json`, true},
		{`{"PRIVILEGED":true,"Cmd":["sh"]}`, true}, // ASCII case-folded by encoding/json
		{`{"privileged":true,"Cmd":["sh"]}`, true}, // (no s/k in "Privileged" to long-s/Kelvin)
	}
	for _, c := range cases {
		if got := denied(c.body); got != c.deny {
			t.Errorf("exec %q: got denied=%v, want %v", c.body, got, c.deny)
		}
	}
}

func TestVolumeCreatePolicy(t *testing.T) {
	denied := func(body string) bool {
		var v volume.CreateRequest
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			return true
		}
		return deviceOpt(v.DriverOpts) != ""
	}
	cases := []struct {
		body string
		deny bool
	}{
		{`{"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}}`, true},
		{`{"Driver":"local","DriverOpts":{"device":"/var/run"}}`, true},
		{`{"Driver":"local","DriverOpts":{"device":":/export","o":"addr=10.0.0.1"}}`, true},
		{`{"Name":"data","Driver":"local"}`, false},
		{`{"Driver":"local","DriverOpts":{"o":"size=100m"}}`, false},
		{`not json`, true},
		{`{"Driver":"local","driveropts":{"o":"bind","device":"/"}}`, true}, // re-cased DriverOpts key
		{`{"Driver":"local","DriverOpts":{"o":"bind","Device":"/"}}`, true}, // re-cased device opt (map key)
	}
	for _, c := range cases {
		if got := denied(c.body); got != c.deny {
			t.Errorf("volume %q: got denied=%v, want %v", c.body, got, c.deny)
		}
	}
}

func TestSecurityOptDeny(t *testing.T) {
	deny := []string{
		"seccomp=unconfined",
		`seccomp={"defaultAction":"SCMP_ACT_ALLOW"}`,
		"apparmor=unconfined",
		"no-new-privileges:false",
		"apparmor=my-profile",
		// assessment finding F3: the daemon also accepts the deprecated `:`-separator form,
		// so a colon-separated CUSTOM profile must be denied identically to the `=` form.
		`seccomp:{"defaultAction":"SCMP_ACT_ALLOW"}`,
		"seccomp:unconfined", // (caught by the flat unconfined check, but assert it anyway)
		"apparmor:my-profile",
	}
	allow := []string{
		"seccomp=default", "apparmor=docker-default", "seccomp=runtime/default",
		"label=user:foo", "no-new-privileges:true",
		// colon form of the defaults / a non-confinement key stays allowed
		"seccomp:default", "apparmor:docker-default", "label:user:foo",
	}
	for _, o := range deny {
		if securityOptDeny(o) == "" {
			t.Errorf("securityOptDeny(%q) = allow, want deny", o)
		}
	}
	for _, o := range allow {
		if securityOptDeny(o) != "" {
			t.Errorf("securityOptDeny(%q) = deny, want allow", o)
		}
	}
}

func TestBuildNetDeny(t *testing.T) {
	q := func(s string) string {
		u, _ := url.Parse("/build?" + s)
		return buildNetDeny(u.Query())
	}
	for _, s := range []string{"networkmode=host", "networkmode=HOST", "networkmode=container:abc", "networkmode=p_gate", "network=host"} {
		if q(s) == "" {
			t.Errorf("buildNetDeny(%q) = allow, want deny", s)
		}
	}
	for _, s := range []string{"", "t=x&nocache=1", "networkmode=bridge", "networkmode=none", "networkmode=p_dev"} {
		if q(s) != "" {
			t.Errorf("buildNetDeny(%q) = deny, want allow", s)
		}
	}
}

func TestGatePatterns(t *testing.T) {
	for _, n := range []string{"p_gate", "gate", "secure_gate"} {
		if !isGateNet(n) {
			t.Errorf("isGateNet(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"p_dev", "", "gateway"} {
		if isGateNet(n) {
			t.Errorf("isGateNet(%q) = true, want false", n)
		}
	}
	for _, n := range []string{"secure_devcontainer_gate-sock", "gate-sock", "x-gate-sock"} {
		if !isGateVol(n) {
			t.Errorf("isGateVol(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"mygate-sock", "gate-socks", "gate", ""} {
		if isGateVol(n) {
			t.Errorf("isGateVol(%q) = true, want false", n)
		}
	}
	// assessment finding F11: the gate/sock matchers fold case now (the rest of the policy
	// does). A re-cased socket-volume name must still be recognised as a shim-socket volume.
	for _, n := range []string{"P_GATE", "Gate", "secure_GATE"} {
		if !isGateNet(n) {
			t.Errorf("isGateNet(%q) = false, want true (case-folded)", n)
		}
	}
	for _, n := range []string{"proj_GATE-SOCK", "Gate-Sock", "proj_App-Sock"} {
		if !isShimSockVol(n) {
			t.Errorf("isShimSockVol(%q) = false, want true (case-folded)", n)
		}
	}
}

// assessment finding F10: a sibling must not create a macvlan/ipvlan network or pin a host
// parent interface (L2 reach the dev container lacks). networkCreateDeny is the pure check.
func TestNetworkCreateDeny(t *testing.T) {
	deny := []string{
		`{"Driver":"macvlan"}`,
		`{"Driver":"ipvlan"}`,
		`{"Driver":"MACVLAN"}`,                            // folded by our ToLower
		`{"Driver":"bridge","Options":{"parent":"eth0"}}`, // host parent NIC
		`{"Driver":"bridge","Options":{"Parent":"eth0"}}`, // map key folded by networkCreateDeny
		`not json`,                                        // fail closed
	}
	allow := []string{
		`{"Driver":"bridge"}`,
		`{"Name":"mynet"}`,
		`{"Driver":"bridge","Options":{"com.docker.network.bridge.name":"br0"}}`,
		`{}`,
	}
	for _, b := range deny {
		if networkCreateDeny([]byte(b)) == "" {
			t.Errorf("networkCreateDeny(%q) = allow, want deny", b)
		}
	}
	for _, b := range allow {
		if networkCreateDeny([]byte(b)) != "" {
			t.Errorf("networkCreateDeny(%q) = deny, want allow", b)
		}
	}
}

// Routing regexes added/extended in this pass (assessment findings F4/F6/F7/F8/F10). These
// are pure-string checks; the handler-level ownership/project gating is in authz_route_test.go.
func TestNewControlPlaneRoutes(t *testing.T) {
	// F6: `start` joins the owned-only lifecycle set.
	for _, p := range []string{"/containers/abc/start", "/v1.53/containers/abc/stop", "/containers/abc/rename"} {
		if m := ctrlRe.FindStringSubmatch(p); m == nil || m[1] != "abc" {
			t.Errorf("ctrlRe failed to gate/capture %q (got %v)", p, m)
		}
	}
	// F4: disconnect is a two-segment route, id in group 1.
	if m := disconnectRe.FindStringSubmatch("/networks/n1/disconnect"); m == nil || m[1] != "n1" {
		t.Errorf("disconnectRe failed on /networks/n1/disconnect (got %v)", m)
	}
	// F10: network create is the single literal segment (not an id -> not inspect).
	if !netCreateRe.MatchString("/v1.45/networks/create") || netCreateRe.MatchString("/networks/abc") {
		t.Errorf("netCreateRe routing wrong")
	}
	// F7: every prune endpoint matches; create/list/inspect do not.
	for _, p := range []string{"/containers/prune", "/volumes/prune", "/images/prune", "/networks/prune", "/build/prune", "/v1.53/containers/prune"} {
		if !pruneRe.MatchString(p) {
			t.Errorf("pruneRe did not match %q", p)
		}
	}
	for _, p := range []string{"/containers/create", "/volumes/create", "/networks/create", "/containers/json"} {
		if pruneRe.MatchString(p) {
			t.Errorf("pruneRe wrongly matched %q", p)
		}
	}
	// F8: plural `docker save` (/images/get) is caught by imagesExportRe; the singular form
	// stays with imageGetRe; neither catches the other and image inspect is untouched.
	if !imagesExportRe.MatchString("/v1.45/images/get") || imagesExportRe.MatchString("/images/alpine/get") {
		t.Errorf("imagesExportRe routing wrong (plural)")
	}
	if !imageGetRe.MatchString("/images/alpine/get") || imageGetRe.MatchString("/images/get") {
		t.Errorf("imageGetRe routing wrong (singular)")
	}
}

func TestRoutingDecodedPath(t *testing.T) {
	// Finding M: the daemon (and net/http) route the DECODED path, so the shim must match
	// on the decoded form. net/url decodes %63 -> 'c', and createRe must then match.
	u, err := url.Parse("/v1.45/containers/%63reate")
	if err != nil {
		t.Fatal(err)
	}
	if !createRe.MatchString(u.Path) {
		t.Errorf("createRe did not match decoded path %q (Finding M regression)", u.Path)
	}
	// trailing-slash / double-slash must NOT be mistaken for create (the daemon 404s them)
	for _, p := range []string{"/containers/create/", "//containers/create", "/foo/containers/create"} {
		uu, _ := url.Parse(p)
		if createRe.MatchString(uu.Path) {
			t.Errorf("createRe wrongly matched %q", uu.Path)
		}
	}
}

// The handler routes on path.Clean(r.URL.Path): non-canonical paths that RESOLVE to a gated
// endpoint must be policed identically to the canonical one (assessment recommendation 1).
func TestRoutingCleanedPath(t *testing.T) {
	for _, dirty := range []string{"//containers/create", "/containers//create", "/foo/../containers/create", "/./containers/create"} {
		if !createRe.MatchString(path.Clean(dirty)) {
			t.Errorf("path.Clean(%q)=%q did not route to create", dirty, path.Clean(dirty))
		}
	}
	// genuinely-different paths must still NOT clean into create
	for _, p := range []string{"/foo/containers/create", "/containers/createx", "/images/create"} {
		if createRe.MatchString(path.Clean(p)) {
			t.Errorf("path.Clean(%q)=%q wrongly routed to create", p, path.Clean(p))
		}
	}
}

func TestReadEndpointRouting(t *testing.T) {
	for _, p := range []string{"/containers/abc/export", "/v1.53/containers/abc/logs", "/containers/abc/top", "/containers/abc/changes", "/containers/abc/json"} {
		m := readRe.FindStringSubmatch(p)
		if m == nil || m[1] != "abc" {
			t.Errorf("readRe failed to gate/capture %q (got %v)", p, m)
		}
	}
	// the list endpoint (no id) and exec-inspect / image-inspect must NOT be caught here
	for _, p := range []string{"/containers/json", "/exec/abc/json", "/images/abc/json", "/containers/abc/attach"} {
		if readRe.MatchString(p) {
			t.Errorf("readRe wrongly matched %q", p)
		}
	}
	if !imageGetRe.MatchString("/v1.53/images/alpine/get") || imageGetRe.MatchString("/images/alpine/json") {
		t.Errorf("imageGetRe routing wrong")
	}
}
