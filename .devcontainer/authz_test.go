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
	"testing"

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
	}
	allow := []string{
		"seccomp=default", "apparmor=docker-default", "seccomp=runtime/default",
		"label=user:foo", "no-new-privileges:true",
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
