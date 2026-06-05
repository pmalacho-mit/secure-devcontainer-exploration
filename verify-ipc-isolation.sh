#!/usr/bin/env bash
# verify-ipc-isolation.sh -- assert the agent uid cannot reach any VS Code
# host-bridge socket after the Part A relocation (TMPDIR=/run/vscode + 0700 dir).
#
# WHAT IT PROVES (empirically, not by assertion -- evidence beats docs):
#   1. It enumerates candidate host-bridge sockets the SAME way an attacker would:
#      the live env, every /proc/<pid>/environ the agent can read (the report's
#      actual VSCODE_IPC_HOOK_CLI leak vector), /proc/net/unix, and /tmp globs.
#   2. For each candidate it tries, AS THE AGENT UID, to connect(). A successful
#      connect is the smoking gun (FAIL). EACCES/EPERM/ENOENT = the desired blocked
#      state (PASS). The only sockets ever actually connected to are already-broken
#      (reachable) ones, so the probe is non-intrusive in the healthy case.
#   3. Positive controls: /run/vscode must be 0700 vscode (observer side), and the
#      agent MUST still reach /run/app/docker.sock (so we know we didn't over-restrict).
#
# USAGE
#   bash .devcontainer/verify-ipc-isolation.sh           # strict: exit 1 on any FAIL
#   bash .devcontainer/verify-ipc-isolation.sh --warn    # never non-zero; just logs
#   (also runnable straight from Claude's Bash tool, where it already runs as agent;
#    the observer-side /run/vscode check is skipped in that case and noted.)
#
# WIRING (run automatically, non-blocking, on every start) -- append to
# devcontainer.json's postStartCommand:
#   ... && bash .devcontainer/verify-ipc-isolation.sh --warn || true
set -u

WARN=0
for a in "$@"; do [ "$a" = "--warn" ] && WARN=1; done
[ "${VERIFY_WARN:-}" = "1" ] && WARN=1

rc=0
say() { printf '[%s] %s\n' "$1" "$2"; }

# --- Observer-side control: only visible to vscode/root (owns the 0700 dir) -----
if [ "$(id -u)" != "2000" ]; then
  d=/run/vscode
  if [ ! -e "$d" ]; then
    say WARN "$d does not exist -- Part A (socket relocation) not applied yet?"
  else
    mode=$(stat -c '%a' "$d" 2>/dev/null || echo '?')
    owner=$(stat -c '%U:%G' "$d" 2>/dev/null || echo '?')
    if [ "$mode" = "700" ] && [ "$owner" = "vscode:vscode" ]; then
      say PASS "$d is $owner mode $mode (agent cannot traverse)"
    else
      say FAIL "$d is $owner mode $mode -- expected vscode:vscode mode 700"
      rc=1
    fi
  fi
else
  say INFO "running as agent (uid 2000); observer-side /run/vscode check skipped"
fi

# --- Agent-perspective probe: run the checks below AS the agent uid -------------
PYRUN="python3"
[ "$(id -u)" = "2000" ] || PYRUN="sudo -u agent python3"

$PYRUN - "$@" <<'PY'
import os, sys, glob, re, socket

warn = ("--warn" in sys.argv) or os.environ.get("VERIFY_WARN") == "1"
def emit(level, msg): print(f"[{level}] {msg}")

PATTERNS  = ("vscode-ipc-*", "vscode-git-*",
             "vscode-ssh-auth-*", "vscode-remote-containers-ipc-*")
PAT_RE    = [re.compile("^" + p.replace("*", ".*") + "$") for p in PATTERNS]
SEARCHDIR = ("/tmp", "/run", "/var/tmp", "/dev/shm")
ENVKEYS   = (b"VSCODE_IPC_HOOK_CLI=", b"SSH_AUTH_SOCK=", b"REMOTE_CONTAINERS_IPC=")

# 1) Enumerate candidate host-bridge sockets, the attacker's way.
cand = set()

for v in ("VSCODE_IPC_HOOK_CLI", "SSH_AUTH_SOCK", "REMOTE_CONTAINERS_IPC"):
    p = os.environ.get(v, "")
    if p.startswith("/"):
        cand.add(p)

for env_path in glob.glob("/proc/[0-9]*/environ"):
    try:
        with open(env_path, "rb") as f:
            blob = f.read()
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        continue  # can't read it (e.g. vscode-owned) -> not an agent-reachable leak
    for kv in blob.split(b"\0"):
        if kv.startswith(ENVKEYS):
            val = kv.split(b"=", 1)[1].decode("utf-8", "replace")
            if val.startswith("/"):
                cand.add(val)

try:
    with open("/proc/net/unix") as f:
        for line in f.read().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 8 and parts[7].startswith("/"):
                base = os.path.basename(parts[7])
                if any(r.match(base) for r in PAT_RE):
                    cand.add(parts[7])
except FileNotFoundError:
    pass

for d in SEARCHDIR:
    for pat in PATTERNS:
        cand.update(glob.glob(os.path.join(d, pat)))
        cand.update(glob.glob(os.path.join(d, "*", pat)))

# 2) Can THIS uid actually connect? (connect() is the ground truth.)
def probe(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(path)
        return ("REACHABLE", "connect() succeeded as this uid")
    except PermissionError:
        return ("blocked", "connect() -> EACCES/EPERM (perms or untraversable parent)")
    except FileNotFoundError:
        return ("gone", "path absent (swept / never created)")
    except ConnectionRefusedError:
        return ("stale", "path present but nothing listening (not a live channel)")
    except OSError as e:
        return ("blocked", f"connect() -> {type(e).__name__}: {e}")
    finally:
        try: s.close()
        except OSError: pass

fails = []
if not cand:
    emit("INFO", "no host-bridge socket candidates discovered (env/proc/glob all clean)")
for path in sorted(cand):
    state, detail = probe(path)
    if state == "REACHABLE":
        emit("FAIL", f"agent CAN reach host-bridge socket: {path} ({detail})")
        fails.append(path)
    elif state == "blocked":
        emit("PASS", f"blocked: {path} ({detail})")
    else:
        emit("INFO", f"{state}: {path} ({detail})")

# 3) Positive control: the legit Docker control plane must still work for agent.
dh = os.environ.get("DOCKER_HOST", "unix:///run/app/docker.sock")
ds = dh[len("unix://"):] if dh.startswith("unix://") else "/run/app/docker.sock"
state, detail = probe(ds)
if state == "REACHABLE":
    emit("PASS", f"agent can reach the Docker control socket {ds} (expected)")
else:
    emit("WARN", f"agent CANNOT reach Docker socket {ds} ({state}: {detail}) -- "
                 "the gate path may be down; fix that before trusting these results")

# 4) Confirm the relocation target is opaque to the agent.
try:
    os.listdir("/run/vscode")
    emit("FAIL", "agent could list /run/vscode -- it is traversable (expected 0700 vscode)")
    fails.append("/run/vscode")
except (PermissionError, FileNotFoundError):
    emit("PASS", "/run/vscode is not traversable by agent (as intended)")

if fails:
    emit("FAIL", f"SUMMARY: {len(fails)} agent-reachable host-bridge channel(s)")
    sys.exit(0 if warn else 1)
emit("PASS", "SUMMARY: no agent-reachable VS Code host-bridge socket")
sys.exit(0)
PY
pyrc=$?

[ "$WARN" = "1" ] && exit 0
[ "$pyrc" -ne 0 ] && rc=1
exit "$rc"
