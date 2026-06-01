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
expect_deny "join the proxy network"    docker run --rm --network gate-proxy-net alpine true

proxy=$(docker ps --filter name=docker-endpoint-proxy -q 2>/dev/null | head -n1)
if [ -n "$proxy" ]; then
  expect_deny "exec into the proxy"     docker exec "$proxy" ls /
else
  echo "  ??  could not find the proxy container to test exec-escape"
fi

echo "== should be ALLOWED =="
expect_allow "plain unprivileged run"   docker run --rm alpine true
expect_allow "list containers"          docker ps

echo
echo "passed: $pass   failed: $fail"
if [ "$fail" -eq 0 ]; then echo "All good - the gate held."; else echo "Some checks FAILED - review above."; fi
