#!/usr/bin/env bash
# Sync the Go shim's pinned toolchain + Docker API types to THIS host's daemon.
#
# The shim parses requests with the daemon's own stdlib + api/types structs, so two pins
# should track the host -- both reported by `docker version`:
#   - the Go TOOLCHAIN         <- daemon Server Go version  (governs encoding/json folding)
#   - github.com/moby/moby/api <- daemon Server API version (the request-schema version)
#
# This is wired into devcontainer.json's `initializeCommand`, so it runs on the HOST before
# every (re)build: it compares the host's versions to the committed pins and, only if they
# DIFFER (e.g. after a Docker Desktop upgrade), rewrites go.mod + authz-proxy.Dockerfile and
# regenerates the committed go.sum -- which then shows up as a reviewable git diff and is
# picked up by the docker-authz rebuild that follows. When already in sync it does nothing
# (no build, no network). It is FAIL-SOFT: any hiccup restores the previous pins and exits 0,
# so a sync problem can never block the container from starting. You can also run it by hand.
#
# Portable (macOS/BSD + Linux/GNU): no `sed -i`; go.mod is rewritten with printf and the
# Dockerfile FROM line with awk. Legacy `github.com/docker/docker` can't track 29+ (moby
# tags those `docker-vX.Y.Z`, which Go's semver resolver rejects); the split-out
# `moby/moby/api` module is versioned by API version, which is what we match.
set -euo pipefail
cd "$(dirname "$0")"
warn() { echo "sync-shim-to-host: $*" >&2; }

# --- read host daemon versions (fail-soft: never block container startup) ---
gover=$(docker version --format '{{.Server.GoVersion}}' 2>/dev/null) \
  || { warn "docker daemon not reachable; keeping committed pins."; exit 0; }
apiver=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null) \
  || { warn "could not read API version; keeping committed pins."; exit 0; }
go_minor=$(printf '%s' "$gover"  | sed -E 's/^go([0-9]+\.[0-9]+).*/\1/')     # go1.25.6 -> 1.25
api_minor=$(printf '%s' "$apiver" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')      # 1.53     -> 1.53
case "$go_minor$api_minor" in *[!0-9.]*|"") warn "could not parse host versions ($gover / $apiver); skipping."; exit 0;; esac

# --- fast path: already in sync? (no network, no docker build) --------------
cur_go=$(sed -n -E 's/^FROM golang:([0-9]+\.[0-9]+)-alpine AS build$/\1/p' authz-proxy.Dockerfile | head -n1)
cur_api=$(sed -n -E 's#^require github\.com/moby/moby/api v([0-9]+\.[0-9]+)\..*#\1#p' go.mod | head -n1)
if [ "$cur_go" = "$go_minor" ] && [ "$cur_api" = "$api_minor" ]; then
  echo "sync-shim-to-host: in sync (golang:$go_minor, moby/moby/api v$api_minor.x match host Go $gover / API $apiver)."
  exit 0
fi
echo "sync-shim-to-host: host (Go $go_minor / API $api_minor) differs from pins (golang:${cur_go:-?} / api v${cur_api:-?}.x) -- resyncing..."

# --- resolve the api module's highest stable patch for this API minor -------
modver=$(curl -fsSL "https://proxy.golang.org/github.com/moby/moby/api/@v/list" 2>/dev/null \
         | grep -E "^v${api_minor}\.[0-9]+$" | sort -V | tail -n1 || true)
modver=${modver:-v${api_minor}.0}

# --- fail-soft: back up the pinned files, restore them on ANY error ---------
backup=$(mktemp -d)
cp go.mod go.sum authz-proxy.Dockerfile "$backup"/ 2>/dev/null || true
restore() { warn "resync failed; restored committed pins (the gate will build on the previous, known-good versions)."; cp "$backup"/go.mod "$backup"/go.sum "$backup"/authz-proxy.Dockerfile ./ 2>/dev/null || true; rm -rf "$backup"; exit 0; }
trap restore ERR

# --- rewrite go.mod (fresh) + the Dockerfile FROM line (both portable) ------
printf 'module authz-proxy\n\ngo %s\n\nrequire github.com/moby/moby/api %s\n' "$go_minor" "$modver" > go.mod
awk -v img="golang:${go_minor}-alpine" \
    '/^FROM golang:[0-9]+\.[0-9]+-alpine AS build$/ { print "FROM " img " AS build"; next } { print }' \
    authz-proxy.Dockerfile > authz-proxy.Dockerfile.tmp && mv authz-proxy.Dockerfile.tmp authz-proxy.Dockerfile

# --- regenerate the committed go.sum (throwaway `go mod tidy` build) --------
# DOCKER_BUILDKIT=0 so this also works when run by hand INSIDE the dev container, where the
# gate denies buildx's privileged helper. On the host (initializeCommand) the gate isn't up,
# so it talks to the real daemon directly.
echo "  regenerating go.sum..."
tdir=$(mktemp -d); cp go.mod ./*.go "$tdir"/
cat > "$tdir/Dockerfile" <<EOF
FROM golang:${go_minor}-alpine
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN go mod tidy
EOF
DOCKER_BUILDKIT=0 docker build -t authz-sync-tidy "$tdir" >/dev/null
cid=$(docker create authz-sync-tidy)
docker cp "$cid":/src/go.mod ./go.mod
docker cp "$cid":/src/go.sum ./go.sum
docker rm "$cid" >/dev/null; docker rmi -f authz-sync-tidy >/dev/null; rm -rf "$tdir"

# --- validate the new pins compile + pass before we let the gate rebuild ----
echo "  running unit tests..."
DOCKER_BUILDKIT=0 docker build --target test -t authz-sync-test -f authz-proxy.Dockerfile . >/dev/null
docker rmi -f authz-sync-test >/dev/null

trap - ERR; rm -rf "$backup"
echo "sync-shim-to-host: updated -> golang:$go_minor + github.com/moby/moby/api $modver (review the git diff; the docker-authz rebuild will pick it up)."
