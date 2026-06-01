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
  docker rm -f "$own" >/dev/null 2>&1
fi

# Attach is the same risk class as exec (reads, and can write, a container's I/O), so
# attaching to a container we DON'T own must be blocked -- otherwise the dev container
# could read/inject the I/O of unrelated host containers. `timeout` guards the hole
# case (a correct gate denies with 403 immediately; only a broken gate would stream).
if [ -n "$proxy" ]; then
  expect_deny "attach to a container we don't own" timeout 5 docker attach --no-stdin "$proxy"
fi

# Volume-mount escape (CVE-class): the built-in `local` driver can bind a host path
# (type=none,o=bind,device=/), turning a "named volume" into a host bind that the
# Binds/Mounts-bind checks never see. Two sub-vectors, both must be blocked:
echo "== volume-mount escape (must be BLOCKED) =="
# (1) creating a host-bind volume via /volumes/create (was uninspected)
expect_deny "volume create binding host root /" \
  docker volume create --driver local --opt type=none --opt o=bind --opt device=/ escvol
docker volume rm escvol >/dev/null 2>&1   # cleanup if an old shim let it through
# (2) inlining the host bind directly in `docker run --mount` (no separate create)
expect_deny "run with inline host-bind volume (device=/)" \
  docker run --rm --mount 'type=volume,dst=/host,volume-driver=local,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/' alpine true
# control: a plain named volume (no host device) is still fine
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

echo
echo "passed: $pass   failed: $fail"
if [ "$fail" -eq 0 ]; then echo "All good - the gate held."; else echo "Some checks FAILED - review above."; fi
