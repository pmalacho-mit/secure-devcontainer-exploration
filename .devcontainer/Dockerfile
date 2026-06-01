FROM mcr.microsoft.com/devcontainers/base:debian

# Docker CLI only (the daemon is never started here; all calls go to the shim).
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

# (Optional hardening: the base image grants `vscode` passwordless sudo. It does
#  NOT weaken the Docker gate — the dev container never sees the real socket — but
#  if you want a stricter sandbox for an escape test, uncomment the next line.)
# RUN rm -f /etc/sudoers.d/* && gpasswd -d vscode sudo 2>/dev/null || true
