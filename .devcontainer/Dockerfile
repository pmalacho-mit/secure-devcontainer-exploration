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

# --- F1 / cont.21: uid-separate untrusted (agent) workloads from the extension host ---
# The VS Code extension host runs as `remoteUser` (vscode). A SAME-UID process can
# `kill -USR1` it to open its in-process V8 inspector (SIGUSR1 is a signal, NOT ptrace,
# so ptrace_scope does not stop it), attach over the Chrome DevTools Protocol (= arbitrary
# JS inside the extension host), and call `vscode.workspace.fs` over `vscode-local://` for
# arbitrary HOST read+write. No in-container Docker control can revoke this -- it is a
# property of running untrusted code at the extension host's own uid, not of Docker. The
# structural fix is uid separation: run untrusted code as a DIFFERENT, lower-privileged
# user, so a SIGUSR1 to the vscode-owned extension host returns EPERM and the inspector
# never opens. (NODE_OPTIONS/--inspect=false does NOT help -- SIGUSR1 re-enables it.)
#
# We add an unprivileged `agent` user (uid 2000, NO sudo) and drop the integrated terminal
# into it (see devcontainer.json's "agent" terminal profile). The VS Code server + extension
# host stay `vscode`; the agent CLI and everything it spawns (npm installs, the browser
# workflow, every shell command -- the actual untrusted surface) run as `agent`, which
# cannot signal the vscode-owned extension host. See docs/DESIGN.md cont. 21.
RUN useradd --create-home --shell /bin/bash --uid 2000 agent \
    && install -d -m 700 -o agent -g agent /home/agent/.tmp \
    # Share the vscode group so `agent` can use the bind-mounted /workspace and the docker
    # socket. `agent` is deliberately NOT in the sudo group -- it has no escalation path.
    && usermod -aG vscode agent \
    # The ONLY privilege transition we add: let the (sudo-capable) vscode terminal launcher
    # AND the claudeProcessWrapper drop into `agent` without a password. `agent` itself has no
    # sudo, so there is no path back up to vscode/root once a shell is running as agent. SETENV
    # lets the claude wrapper pass `--preserve-env` (so the extension's injected auth/session
    # env reaches Claude) -- a downward (vscode->agent) transition, so it grants no escalation.
    && printf 'vscode ALL=(agent) NOPASSWD:SETENV: ALL\n' > /etc/sudoers.d/10-vscode-to-agent \
    && chmod 0440 /etc/sudoers.d/10-vscode-to-agent \
    # Scrub the VS Code IPC channels in agent's interactive shells too (login shells already
    # get it via /etc/profile.d; this prepends the source line above .bashrc's interactive
    # guard, exactly as the vscode .bashrc is wired above).
    && printf '. /usr/local/share/harden-vscode-ipc.sh\n' | cat - /home/agent/.bashrc > /tmp/.bashrc.agent \
    && mv /tmp/.bashrc.agent /home/agent/.bashrc \
    && chown agent:agent /home/agent/.bashrc

# The `anthropic.claude-code` extension spawns its bundled `claude` binary as a DIRECT child
# of the extension host (same uid, vscode), NOT in a terminal -- so the terminal profile above
# does NOT reach it. devcontainer.json sets `claudeCode.claudeProcessWrapper` to this wrapper,
# which re-execs the real CLI as `agent` so Claude's Bash tool runs every command as `agent`
# (cannot signal the extension host). See the script + docs/DESIGN.md cont. 21.
COPY .devcontainer/claude-as-agent.sh /usr/local/bin/claude-as-agent

# DOCKER_HOST is set by compose for PID 1, but the agent terminal is a `sudo -i` LOGIN shell
# with a clean env, so expose the (fixed) socket path to ALL login shells via profile.d. The
# path is pinned by docker-compose.yml (LISTEN_SOCK=/run/app/docker.sock on the app-sock
# volume); without this the agent shell would have no route to Docker.
RUN chmod 0555 /usr/local/bin/claude-as-agent \
    && printf 'export DOCKER_HOST=unix:///run/app/docker.sock\n' > /etc/profile.d/10-docker-host.sh \
    && chmod 0444 /etc/profile.d/10-docker-host.sh

# --- F1 / cont.21: drop vscode's BROAD passwordless sudo --------------------------------
# The base image ships `/etc/sudoers.d/vscode` (`vscode ALL=(ALL) NOPASSWD: ALL`). Until now
# that broad rule was inert ONLY because `no-new-privileges` neutralized sudo's setuid bit
# (REMEDIATION-devcontainer.md). F1 requires `no-new-privileges` to be OFF on `app` (so the
# vscode->agent sudo drop works), which would re-arm that broad rule -- a vscode shell could
# `sudo -i` to root. So we remove it here and keep ONLY the narrow `10-vscode-to-agent` rule
# created above: the sole remaining privilege transition is the intended DOWNWARD vscode->agent.
# (`vscode` is not in the `sudo` group -- the file is its only escalation path -- but we drop
# the group membership too, defensively, in case a future base image adds it.) `agent` has no
# sudo of any kind. We deliberately do NOT `rm -f /etc/sudoers.d/*`: that would also delete the
# load-bearing `10-vscode-to-agent` rule and the agent terminal + Claude wrapper could not launch.
RUN rm -f /etc/sudoers.d/vscode \
    && gpasswd -d vscode sudo 2>/dev/null || true
