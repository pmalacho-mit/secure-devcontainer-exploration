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
dev_name=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|[-_])dev$' | head -n1)
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
    s = socket.socket(); s.settimeout(4); s.connect(("docker-authz", 2375))
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
    s = socket.socket(); s.settimeout(4); s.connect(("docker-authz", 2375))
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
# The socket now lives on a named volume; a sibling must not be able to mount it and
# talk to tecnativa directly (the network bypass reborn as a volume bypass).
gsock=$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|[-_])gate-sock$' | head -n1)
gsock=${gsock:-proj_gate-sock}   # fall back to a plausible name so the deny still fires
expect_deny "mount the gate socket volume" docker run --rm --mount "type=volume,source=$gsock,dst=/g" alpine true

echo
echo "passed: $pass   failed: $fail"
if [ "$fail" -eq 0 ]; then echo "All good - the gate held."; else echo "Some checks FAILED - review above."; fi
