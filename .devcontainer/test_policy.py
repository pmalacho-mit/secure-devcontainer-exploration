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

# --- is_gate_net suffix branch ---------------------------------------------
assert shim.is_gate_net("p_gate") is True, "p_gate should match"
assert shim.is_gate_net("gate") is True, "bare 'gate' should match"
assert shim.is_gate_net("p_dev") is False, "p_dev should not match"
assert shim.is_gate_net("") is False, "empty should not match"
ok += 4

print("\npolicy unit tests: passed=%d failed=%d" % (ok, bad))
sys.exit(1 if bad else 0)
