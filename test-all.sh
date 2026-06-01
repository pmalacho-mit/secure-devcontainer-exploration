#!/usr/bin/env bash
# Run the full gate test suite from inside the dev container.
set -e
./test-escape.sh
./test-comms.sh
# Hermetic policy unit tests are now Go; they run in the shim image's `test` build stage
# (the dev container has no `go` toolchain). DOCKER_BUILDKIT=0 forces the daemon's
# embedded builder -- the default buildx driver would boot a privileged helper the gate
# (correctly) denies.
env DOCKER_BUILDKIT=0 docker build --target test -f .devcontainer/authz-proxy.Dockerfile .devcontainer
