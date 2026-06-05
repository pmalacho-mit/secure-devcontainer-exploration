#!/usr/bin/env bash
# Run this INSIDE the dev container.
#
# Verifies the legitimate workflow reachability the gate is meant to preserve. Since
# siblings can no longer bind-mount the workspace (see DESIGN.md cont. 7), the workflow
# shares file changes with them over three other channels instead -- this confirms all
# three work, plus plain network reachability in both directions:
#   A & B. HTTP over the shared dev network (also transfers file content).
#   C.     docker exec  -- write/read files inside a sibling (the control-layer pattern
#          the real workflow drives playwright with, and reads files out via `cat`).
#   D.     docker cp    -- copy files into and out of a sibling we own.
# This is the positive counterpart to test-escape.sh (which checks what must be
# blocked); here we check what must KEEP working.
set -u
pass=0; fail=0
check() {  # check "desc" "expected" "actual"
  local desc="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  ok  : $desc"; pass=$((pass+1))
  else
    echo "  FAIL: $desc (expected '$expected', got '$actual')"; fail=$((fail+1))
  fi
}

# Discover OUR OWN dev network from what this container is actually attached to, not by
# grepping the global `docker network ls` -- the host can now host many projects' `_dev`
# networks at once (each dev container gets its own, see DESIGN.md per-devcontainer
# isolation), so "first `_dev` in the global list" picks a FOREIGN project's network. The
# dev container is attached to exactly its own `<project>_dev`, so read it off ourselves.
DEV=$(docker inspect "$(hostname)" \
  --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' 2>/dev/null \
  | grep -E '(^|[-_])dev$' | head -n1)
if [ -z "$DEV" ]; then echo "could not find our own dev network"; exit 1; fi
echo "dev network: $DEV"

# The dev container's own IP on the dev network (it is attached to it by compose).
MYIP=$(docker inspect "$(hostname)" \
  --format "{{ (index .NetworkSettings.Networks \"$DEV\").IPAddress }}" 2>/dev/null)
if [ -z "$MYIP" ]; then echo "could not resolve dev container IP on $DEV"; exit 1; fi
echo "dev container IP on $DEV: $MYIP"

SRVPID=""; CTR=""; FS=""
cleanup() {
  [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null
  [ -n "$CTR" ] && docker rm -f "$CTR" >/dev/null 2>&1
  [ -n "$FS" ] && docker rm -f "$FS" >/dev/null 2>&1
  rm -f "/tmp/cp_src_$$" "/tmp/cp_roundtrip_$$" "/tmp/cp_seed_$$" 2>/dev/null
}
trap cleanup EXIT

# ---- Direction A (HTTP): sibling container -> dev container server -----------
echo "== Direction A (HTTP): a started container reaches a server in the dev container =="
MSG_A="hello-from-devcontainer-server"
TMPDIR_A=$(mktemp -d)
echo "$MSG_A" > "$TMPDIR_A/payload.txt"
python3 -m http.server 8099 --bind 0.0.0.0 --directory "$TMPDIR_A" >/dev/null 2>&1 &
SRVPID=$!
sleep 1
GOT_A=$(docker run --rm --network "$DEV" curlimages/curl:latest \
          -s --max-time 15 "http://$MYIP:8099/payload.txt" 2>/dev/null | tr -d '\r\n')
check "sibling container fetched the dev container's server" "$MSG_A" "$GOT_A"
kill "$SRVPID" 2>/dev/null; SRVPID=""
rm -rf "$TMPDIR_A"

# ---- Direction B (HTTP): dev container -> sibling container server -----------
echo "== Direction B (HTTP): the dev container reaches a server in a started container =="
MSG_B="hello-from-started-container"
CTR=commtest_$$
docker run -d --name "$CTR" --network "$DEV" python:3-alpine \
  sh -c "echo '$MSG_B' > /payload.txt; cd /; python3 -m http.server 8088 --bind 0.0.0.0" \
  >/dev/null 2>&1
# wait for it to come up
CIP=""
for _ in $(seq 1 15); do
  CIP=$(docker inspect "$CTR" \
    --format "{{ (index .NetworkSettings.Networks \"$DEV\").IPAddress }}" 2>/dev/null)
  [ -n "$CIP" ] && curl -s --max-time 2 "http://$CIP:8088/payload.txt" >/dev/null 2>&1 && break
  sleep 1
done
echo "started container IP on $DEV: $CIP"
GOT_B_IP=$(curl -s --max-time 15 "http://$CIP:8088/payload.txt" 2>/dev/null | tr -d '\r\n')
check "dev container fetched the sibling server by IP" "$MSG_B" "$GOT_B_IP"
GOT_B_DNS=$(curl -s --max-time 15 "http://$CTR:8088/payload.txt" 2>/dev/null | tr -d '\r\n')
check "dev container fetched the sibling server by docker DNS name" "$MSG_B" "$GOT_B_DNS"
docker rm -f "$CTR" >/dev/null 2>&1; CTR=""

# ---- One long-lived sibling for the exec & cp channels ----------------------
# It seeds a known file at startup so the "out" directions don't depend on the "in".
SEED="seeded-in-sibling-at-start"
FS=fileshare_$$
docker run -d --name "$FS" --network "$DEV" alpine \
  sh -c "echo '$SEED' > /seed.txt; sleep 600" >/dev/null 2>&1
for _ in $(seq 1 15); do            # wait until it's running and exec-able
  docker exec "$FS" true >/dev/null 2>&1 && break
  sleep 1
done

# ---- Channel C (docker exec): write/read files inside the sibling -----------
echo "== Channel C (docker exec): mutate and read sibling files =="
MSG_E="written-into-sibling-via-exec"
docker exec "$FS" sh -c "echo '$MSG_E' > /from_exec.txt" >/dev/null 2>&1
GOT_E=$(docker exec "$FS" cat /from_exec.txt 2>/dev/null | tr -d '\r\n')
check "exec wrote then read a file inside the sibling" "$MSG_E" "$GOT_E"
GOT_ESEED=$(docker exec "$FS" cat /seed.txt 2>/dev/null | tr -d '\r\n')
check "exec read a sibling file out via 'docker exec cat'" "$SEED" "$GOT_ESEED"

# ---- Channel D (docker cp): copy files in and out of the owned sibling -------
echo "== Channel D (docker cp): copy files into and out of the sibling =="
# OUT: copy the seeded sibling file into the dev container.
docker cp "$FS":/seed.txt "/tmp/cp_seed_$$" >/dev/null 2>&1
GOT_CPOUT=$(cat "/tmp/cp_seed_$$" 2>/dev/null | tr -d '\r\n')
check "docker cp copied a sibling file OUT to the dev container" "$SEED" "$GOT_CPOUT"
# IN: copy a dev-container file into the sibling, then back OUT to confirm it landed
# (a pure-cp round-trip, independent of the exec channel).
MSG_CP="edited-in-devcontainer-then-cp-in"
echo "$MSG_CP" > "/tmp/cp_src_$$"
docker cp "/tmp/cp_src_$$" "$FS":/injected.txt >/dev/null 2>&1
docker cp "$FS":/injected.txt "/tmp/cp_roundtrip_$$" >/dev/null 2>&1
GOT_CPIN=$(cat "/tmp/cp_roundtrip_$$" 2>/dev/null | tr -d '\r\n')
check "docker cp copied a file INTO the sibling (verified round-trip)" "$MSG_CP" "$GOT_CPIN"

docker rm -f "$FS" >/dev/null 2>&1; FS=""
rm -f "/tmp/cp_src_$$" "/tmp/cp_roundtrip_$$" "/tmp/cp_seed_$$"

echo
echo "passed: $pass   failed: $fail"
if [ "$fail" -eq 0 ]; then echo "All good - network (HTTP), docker exec, and docker cp all work both ways."; else echo "Some checks FAILED - review above."; fi
