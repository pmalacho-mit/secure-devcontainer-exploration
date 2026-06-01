# Multi-stage Go build for the body-inspecting shim (cont.16, ported from Python).
# Both pins track THIS host's daemon, and both are values `docker version` reports -- run
# `./sync-shim-to-host.sh` to re-derive them after a Docker Desktop upgrade:
#   - golang:1.25  <- daemon Server Go version (go1.25.6). This is the LOAD-BEARING match:
#     the parser-differential defense relies on encoding/json's case/Unicode field-folding,
#     a property of the Go TOOLCHAIN, not of moby. Same Go => same folding as the daemon.
#   - github.com/moby/moby/api v1.53.0 <- daemon Server API version (1.53). This is the
#     modern, maintained types module, versioned by *API version* (the request-schema we
#     parse) -- exactly the right thing to match. (The legacy github.com/docker/docker
#     module can't go past v28: moby tags 29+ as `docker-vX.Y.Z`, which Go's semver
#     resolver rejects -- so it was frozen and the API types split out here.)
# go.mod + go.sum are committed (hashes pinned) so `go mod download` is reproducible.
# The `test` stage runs the hermetic policy unit tests; build it with `--target test`.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

FROM build AS test
# `-v` so the pass/fail of every test is visible in `docker build` output; the legacy
# (DOCKER_BUILDKIT=0) builder only streams RUN output when this layer is NOT cached, so
# you'll see results whenever a `.go` file changed (and `--no-cache` forces a re-run).
RUN go vet ./... && go test -v ./...

FROM build AS bin
RUN CGO_ENABLED=0 go build -trimpath -o /authz-proxy .

FROM alpine:3.20
COPY --from=bin /authz-proxy /authz-proxy
ENTRYPOINT ["/authz-proxy"]
