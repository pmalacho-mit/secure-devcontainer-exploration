FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Install the Docker CLI **client only** — the daemon is never started here; all
# calls go to the shim via DOCKER_HOST=tcp://docker-authz:2375.
#
# Why the official Docker apt repo (docker-ce-cli) instead of the distro
# `docker.io` package: distro packaging of the client is unreliable across
# releases. On Debian 13 (trixie) `docker.io` ships the DAEMON only
# (dockerd/docker-proxy/docker-init) and the `docker` client was split into a
# separate package, so `docker.io` gives you no `/usr/bin/docker`; Ubuntu's
# packaging has similar drift. `docker-ce-cli` is client-only and stable across
# versions, and pulling only it keeps the daemon (which we never want here) out
# of the image entirely.
#
# python3 is here purely so the gate's own checks can run from inside the dev
# container (`.devcontainer/test_policy.py`, hermetic). It does NOT touch the gate.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
         | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
         > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# (Optional hardening: the base image grants `vscode` passwordless sudo. It does
#  NOT weaken the Docker gate — the dev container never sees the real socket — but
#  if you want a stricter sandbox for an escape test, uncomment the next line.)
# RUN rm -f /etc/sudoers.d/* && gpasswd -d vscode sudo 2>/dev/null || true
