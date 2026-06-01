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
# container (`test-escape.sh` fires raw-socket probes -- smuggling, key-confusion,
# path-encoding -- via python3). It does NOT touch the gate. The hermetic policy unit
# tests are now Go and run in the shim image's `test` build stage, not here.
#
# docker-buildx-plugin: enables `docker buildx` / BuildKit from the CLI. With the
# default `docker` driver, a buildx build drives the DAEMON's embedded BuildKit over
# `/build` + `/session` (gRPC) -- the SAME path dockerode's `version: "2"` builds use
# -- so it lets us exercise the BuildKit route through the gate (cont. 9/10) instead
# of only reasoning about it. It needs no daemon config; tecnativa already allows
# BUILD + SESSION and the shim relays the hijacked /session stream.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
         | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
         > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

# --- VS Code IPC host-bridge hardening (defence-in-depth) -------------------
# Remote-Containers hands the dev container host-reaching channels via /tmp sockets
# + env vars (forwarded SSH agent, git-credential broker, `code` IPC). The Docker
# gate does NOT cover these (open vector in docs/DESIGN.md, cont. 13). Scrub them
# from every shell the agent spawns, three ways so no shell flavour slips through:
#   - BASH_ENV   -> sourced by non-interactive `bash -c` (what coding agents use).
#   - profile.d  -> sourced by login shells.
#   - prepended ABOVE .bashrc's interactive guard -> interactive shells (the guard
#     `case $- in *i*) ;; *) return ;; esac` early-returns for non-interactive, so
#     the source line must come before it).
# In-container => defeatable by a same-privilege attacker (re-globbing /tmp); the
# tamper-resistant control is the host-side forwarding toggles. See the script.
COPY .devcontainer/harden-vscode-ipc.sh /usr/local/share/harden-vscode-ipc.sh
ENV BASH_ENV=/usr/local/share/harden-vscode-ipc.sh
RUN chmod 0444 /usr/local/share/harden-vscode-ipc.sh \
    && ln -sf /usr/local/share/harden-vscode-ipc.sh /etc/profile.d/00-harden-vscode-ipc.sh \
    && printf '. /usr/local/share/harden-vscode-ipc.sh\n' > /tmp/.bashrc.new \
    && cat /home/vscode/.bashrc >> /tmp/.bashrc.new \
    && mv /tmp/.bashrc.new /home/vscode/.bashrc \
    && chown vscode:vscode /home/vscode/.bashrc

# (Optional hardening: the base image grants `vscode` passwordless sudo. It does
#  NOT weaken the Docker gate — the dev container never sees the real socket — but
#  if you want a stricter sandbox for an escape test, uncomment the next line.)
# RUN rm -f /etc/sudoers.d/* && gpasswd -d vscode sudo 2>/dev/null || true
