#!/usr/bin/env python3
"""Hermetic unit tests for the shim's pure policy logic (no Docker daemon needed).

Covers `check_create` (the create-body allowlist) and the suffix branch of
`is_gate_net`. The daemon-dependent paths (discovery, exec/connect membership
checks) are exercised by `test-escape.sh` against a live stack instead.

Run:  python3 .devcontainer/test_policy.py
"""
import importlib.util
import json
import os
import sys

# Configure the module's env BEFORE import (read at import time).
os.environ["ALLOWED_BIND_PREFIXES"] = "/host/workspace"
HERE = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location("authz_proxy", os.path.join(HERE, "authz-proxy.py"))
shim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shim)

# Never touch the network during create-policy tests: pretend nothing was
# discovered (the gate is then recognised only by its `_gate` suffix here).
shim.gate_ids = lambda: set()

ok = 0
bad = 0


def expect(desc, body, want_deny):
    global ok, bad
    reason = shim.check_create(json.dumps(body).encode() if isinstance(body, (dict, list)) else body)
    denied = reason is not None
    if denied == want_deny:
        ok += 1
    else:
        bad += 1
        print("  FAIL: %s -> reason=%r (wanted %s)" % (desc, reason, "deny" if want_deny else "allow"))


DENY = True
ALLOW = False

# --- denials ---------------------------------------------------------------
expect("privileged",            {"HostConfig": {"Privileged": True}}, DENY)
expect("cap add",               {"HostConfig": {"CapAdd": ["SYS_ADMIN"]}}, DENY)
expect("devices",               {"HostConfig": {"Devices": [{"PathOnHost": "/dev/sda"}]}}, DENY)
expect("device requests",       {"HostConfig": {"DeviceRequests": [{"Count": -1}]}}, DENY)
expect("device cgroup rules",   {"HostConfig": {"DeviceCgroupRules": ["c 1:1 rwm"]}}, DENY)
expect("VolumesFrom",           {"HostConfig": {"VolumesFrom": ["other"]}}, DENY)
expect("PidMode host",          {"HostConfig": {"PidMode": "host"}}, DENY)
expect("IpcMode host",          {"HostConfig": {"IpcMode": "host"}}, DENY)
expect("UTSMode host",          {"HostConfig": {"UTSMode": "host"}}, DENY)
expect("UsernsMode host",       {"HostConfig": {"UsernsMode": "host"}}, DENY)
expect("NetworkMode host",      {"HostConfig": {"NetworkMode": "host"}}, DENY)
expect("NetworkMode container", {"HostConfig": {"NetworkMode": "container:abc123"}}, DENY)
expect("NetworkMode gate suffix", {"HostConfig": {"NetworkMode": "myproj_gate"}}, DENY)
expect("EndpointsConfig gate",  {"NetworkingConfig": {"EndpointsConfig": {"myproj_gate": {}}}}, DENY)
expect("seccomp unconfined",    {"HostConfig": {"SecurityOpt": ["seccomp=unconfined"]}}, DENY)
expect("apparmor unconfined",   {"HostConfig": {"SecurityOpt": ["apparmor=unconfined"]}}, DENY)
expect("nnp false",             {"HostConfig": {"SecurityOpt": ["no-new-privileges:false"]}}, DENY)
expect("bind outside workspace",{"HostConfig": {"Binds": ["/etc:/etc"]}}, DENY)
expect("mount outside workspace",{"HostConfig": {"Mounts": [{"Type": "bind", "Source": "/etc", "Target": "/etc"}]}}, DENY)
expect("unparseable body",      b"not json", DENY)

# --- allowances (the workflow's actual shapes) -----------------------------
expect("plain peer on dev net", {"Image": "x", "HostConfig": {"NetworkMode": "myproj_dev", "AutoRemove": True, "PortBindings": {}}}, ALLOW)
expect("no HostConfig",         {"Image": "x"}, ALLOW)
expect("bind inside workspace", {"HostConfig": {"Binds": ["/host/workspace/sub:/w"]}}, ALLOW)
expect("bind exactly workspace",{"HostConfig": {"Binds": ["/host/workspace:/w"]}}, ALLOW)
expect("mount inside workspace",{"HostConfig": {"Mounts": [{"Type": "bind", "Source": "/host/workspace/x", "Target": "/x"}]}}, ALLOW)

# --- volume escape: inline host-bind local volume in the create body --------
# The CVE-class bypass: a `volume` mount that inlines DriverConfig.Options.device
# is a host bind in disguise; check_create must catch it (Binds/Mounts-bind don't).
INLINE = lambda dev: {"HostConfig": {"Mounts": [
    {"Type": "volume", "Target": "/host",
     "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {
         "type": "none", "o": "bind", "device": dev}}}}]}}
expect("inline vol bind host root",  INLINE("/"), DENY)
expect("inline vol bind host etc",   INLINE("/etc"), DENY)
expect("inline vol nfs-style device", INLINE(":/etc"), DENY)         # leading ':' stripped
expect("inline vol bind in workspace", INLINE("/host/workspace/v"), ALLOW)
expect("plain named vol (no opts)",  {"HostConfig": {"Mounts": [
    {"Type": "volume", "Source": "data", "Target": "/d"}]}}, ALLOW)

# --- check_volume_create: the /volumes/create gate -------------------------
def expect_vol(desc, body, want_deny):
    global ok, bad
    reason = shim.check_volume_create(json.dumps(body).encode() if isinstance(body, (dict, list)) else body)
    if (reason is not None) == want_deny:
        ok += 1
    else:
        bad += 1
        print("  FAIL(vol): %s -> reason=%r (wanted %s)" % (desc, reason, "deny" if want_deny else "allow"))

expect_vol("vol bind host root /",   {"Driver": "local", "DriverOpts": {"type": "none", "o": "bind", "device": "/"}}, DENY)
expect_vol("vol bind /var/run",      {"Driver": "local", "DriverOpts": {"type": "none", "o": "bind", "device": "/var/run"}}, DENY)
expect_vol("vol rbind host root",    {"Driver": "local", "DriverOpts": {"type": "none", "o": "rbind", "device": "/"}}, DENY)
expect_vol("vol nfs-style device",   {"Driver": "local", "DriverOpts": {"device": ":/export", "o": "addr=10.0.0.1"}}, DENY)
expect_vol("vol Options key variant",{"Driver": "local", "Options": {"device": "/etc"}}, DENY)
expect_vol("vol bind inside ws",     {"Driver": "local", "DriverOpts": {"type": "none", "o": "bind", "device": "/host/workspace/v"}}, ALLOW)
expect_vol("plain vol (no opts)",    {"Name": "data", "Driver": "local"}, ALLOW)
expect_vol("vol no device opt",      {"Driver": "local", "DriverOpts": {"o": "size=100m"}}, ALLOW)
expect_vol("unparseable vol body",   b"not json", DENY)

# --- create_vol_refs: which named volumes hit the daemon backstop ----------
# By-reference volumes (no inline DriverConfig) are extracted; inline-opt and bind
# mounts are NOT (check_create handles those purely, no daemon round-trip needed).
assert shim.create_vol_refs({"HostConfig": {"Mounts": [
    {"Type": "volume", "Source": "byref", "Target": "/a"}]}}) == {"byref"}, "by-ref vol extracted"
assert shim.create_vol_refs({"HostConfig": {"Mounts": [
    {"Type": "volume", "Source": "inline", "Target": "/a",
     "VolumeOptions": {"DriverConfig": {"Options": {"device": "/"}}}}]}}) == set(), "inline vol not in backstop set"
assert shim.create_vol_refs({"HostConfig": {"Mounts": [
    {"Type": "bind", "Source": "/host/workspace", "Target": "/a"}]}}) == set(), "bind not in backstop set"
ok += 3

# --- is_gate_net suffix branch ---------------------------------------------
assert shim.is_gate_net("p_gate") is True, "p_gate should match"
assert shim.is_gate_net("gate") is True, "bare 'gate' should match"
assert shim.is_gate_net("p_dev") is False, "p_dev should not match"
assert shim.is_gate_net("") is False, "empty should not match"
ok += 4

# --- is_upgrade: connection-hijack detection (exec start / attach streaming) -
# A hijack request must pass through verbatim; a plain request must be rewritten
# to `Connection: close`. Misclassifying a plain request as upgrade would leak
# keep-alive; misclassifying a hijack as plain reintroduces the 502.
assert shim.is_upgrade(b"POST /exec/x/start HTTP/1.1\r\nUpgrade: tcp\r\nConnection: Upgrade") is True
assert shim.is_upgrade(b"POST /containers/x/attach HTTP/1.1\r\nConnection: Upgrade") is True
assert shim.is_upgrade(b"POST /containers/x/attach HTTP/1.1\r\nupgrade: tcp") is True  # case-insensitive
assert shim.is_upgrade(b"GET /version HTTP/1.1\r\nConnection: close") is False
assert shim.is_upgrade(b"POST /containers/create HTTP/1.1\r\nContent-Length: 5") is False
# request line must not be sniffed for the word (only header lines count)
assert shim.is_upgrade(b"GET /upgrade HTTP/1.1\r\nHost: d") is False
# rewrite(): upgrade preserves headers verbatim; non-upgrade forces close
assert shim.rewrite(b"POST /exec/x/start HTTP/1.1\r\nUpgrade: tcp\r\nConnection: Upgrade", True) \
    == b"POST /exec/x/start HTTP/1.1\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n"
assert b"Connection: close" in shim.rewrite(b"GET /version HTTP/1.1\r\nConnection: keep-alive", False)
assert b"keep-alive" not in shim.rewrite(b"GET /version HTTP/1.1\r\nConnection: keep-alive", False).lower()
ok += 9

print("\npolicy unit tests: passed=%d failed=%d" % (ok, bad))
sys.exit(1 if bad else 0)
