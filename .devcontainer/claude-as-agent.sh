#!/bin/sh
# claude-as-agent -- run the Claude Code CLI as the unprivileged `agent` uid (F1 / cont.21).
#
# WHY. The VS Code `anthropic.claude-code` extension spawns its OWN bundled `claude` binary
# (…/extensions/anthropic.claude-code-*/resources/native-binary/claude) as a DIRECT
# child_process of the extension host -- NOT in an integrated terminal, and by absolute path
# (there is no `claude` on PATH). So neither the `terminal.integrated.defaultProfile` drop-to-
# agent NOR a PATH shim reaches it: Claude, and every command its Bash tool runs, would stay
# `vscode` -- the SAME uid as the extension host -- and a prompt-injected command could
# `kill -USR1` the extension host to open its V8 inspector and read/write the host fs.
#
# FIX. The extension's `claudeCode.claudeProcessWrapper` setting (devcontainer.json) points the
# extension at THIS script instead of the bundled binary. We re-exec the real CLI as `agent`,
# which cannot signal the vscode-owned extension host (SIGUSR1 -> EPERM). Claude's Bash tool
# then runs every command as `agent`, breaking the injection -> shell -> inspector-hijack chain.
# (This does NOT touch the trusted-extension supply-chain residual -- that stays host-side.)
#
# Robust to either invocation form the extension may use:
#   prefix/launcher form:  <this> <real-claude> <args...>   ($1 is an executable)
#   executable-swap form:  <this> <args...>                 ($1 is a flag; we locate the binary)
set -u

if [ "$#" -ge 1 ] && [ -x "$1" ]; then
  :  # prefix form: $1 is already the real claude executable, args follow
else
  # executable-swap form: prepend the bundled claude binary (newest version dir wins).
  real=$(ls -1d /home/*/.vscode-server/extensions/anthropic.claude-code-*/resources/native-binary/claude 2>/dev/null | sort -V | tail -n1)
  if [ -z "$real" ] || [ ! -x "$real" ]; then
    echo "claude-as-agent: cannot locate the bundled claude binary; refusing to run as vscode" >&2
    exit 127  # fail CLOSED -- never silently fall back to the extension-host uid
  fi
  set -- "$real" "$@"
fi

# Already agent (e.g. launched from the agent terminal): run directly -- `agent` has no sudo.
# (Its ~/.claude was seeded by a prior extension-host launch; see seed_agent_login below.)
if [ "$(id -u)" = "2000" ]; then
  exec "$@"
fi

# --- Let agent reach the bundled binary (cont.27) -------------------------------------------
# The extension's `claude` lives at .../​.vscode-server/extensions/anthropic.claude-code-*/​
# resources/native-binary/claude. The binary itself is world-executable (0755) and every dir
# BELOW `extensions` is 0755 -- but VS Code creates `extensions/` itself mode 0700 (vscode:vscode),
# so the `agent` uid (in the `vscode` group, but the dir grants the group nothing) cannot TRAVERSE
# into it to exec the binary: the drop below would die with `env: .../claude: Permission denied`
# (exit 126) -- the cont.26 post-rebuild auth failure. We run as `vscode` here (the dir's owner),
# so before dropping we add GROUP-EXECUTE (traverse only, NOT read) to each ancestor of the binary
# up to `.vscode-server`. agent (vscode group) can then walk to the world-readable binary; it still
# cannot `ls` the dir (no g+r) nor reach anything outside this path. Self-healing across extension
# updates and Rebuilds (the path is re-resolved and re-chmod'd every launch). chmod failures are
# non-fatal (|| true) -- if traverse can't be granted the drop simply fails closed, never as vscode.
grant_agent_traverse() {
  vss="$(getent passwd vscode | cut -d: -f6)/.vscode-server"
  d=$(dirname "$1")
  case "$d" in "$vss"/*) ;; *) return 0 ;; esac   # only ever touch vscode's own server tree
  while [ "$d" != "$vss" ] && [ "$d" != "/" ]; do
    chmod g+x "$d" 2>/dev/null || true
    d=$(dirname "$d")
  done
}
grant_agent_traverse "$1"

# --- Inherit the extension-host user's Claude login (cont.24) -------------------------------
# We run as `vscode` here (the extension spawned us). `vscode` is the user you actually log
# Claude into -- the extension's normal OAuth flow writes its credential to
# /home/vscode/.claude/.credentials.json, mode 0600 (owner-only). Because we drop to the
# separate `agent` uid below (HOME=/home/agent), agent has its OWN, initially-empty store --
# and a Rebuild wipes agent's image-layer home -- so without help you'd have to log Claude in
# a SECOND time, as agent. Instead, while we are still `vscode` (and can read vscode's 0600
# credential), copy it into agent's store, WRITTEN AS agent via the existing vscode->agent
# sudo rule, so it is correctly owned and needs no chown/CAP (the container is cap_drop: ALL).
# agent then launches already authenticated with the same login. We deliberately do NOT touch
# vscode's store, and seed `.claude.json` (onboarding/account state) only when agent has none,
# so we never clobber agent's own session state. If the extension isn't logged in yet, this is
# a no-op and agent comes up unauthenticated until the next launch after you log in.
# Residual: agent and the extension share one Anthropic login. agent runs on vscode's fresh
# token, so it rarely refreshes itself; if it ever does, the rotation is self-healing on the
# next launch (we re-seed from vscode's then-current credential).
seed_agent_login() {
  vh=$(getent passwd vscode | cut -d: -f6) || return 0
  [ -n "${vh:-}" ] || return 0
  cred="$vh/.claude/.credentials.json"
  [ -r "$cred" ] || return 0   # extension not logged in yet -> nothing to inherit
  /usr/bin/sudo -u agent -- /bin/sh -c '
    d="$HOME/.claude"; mkdir -p "$d" && chmod 700 "$d" || exit 0
    umask 077; cat > "$d/.credentials.json"
  ' < "$cred" 2>/dev/null || true
  if [ -r "$vh/.claude.json" ]; then
    /usr/bin/sudo -u agent -- /bin/sh -c '
      [ -e "$HOME/.claude.json" ] || { umask 077; cat > "$HOME/.claude.json"; }
    ' < "$vh/.claude.json" 2>/dev/null || true
  fi
}
seed_agent_login

# Drop vscode -> agent. --preserve-env keeps the auth/session environment the extension
# injected (the NOPASSWD + SETENV rule is in .devcontainer/Dockerfile; the host-reaching VS
# Code IPC vars are already nulled in remoteEnv + harden-vscode-ipc.sh).
#
# HOME=/home/agent is forced via `env` AFTER sudo: --preserve-env would otherwise carry the
# extension host's HOME=/home/vscode into the agent process, and Claude reads/writes its OAuth
# credentials in $HOME/.claude -- a dir `agent` (uid 2000) cannot access (vscode's is mode 700).
# Pointing HOME at agent's own home keeps the untrusted agent in its OWN credential store
# (seeded above from your login, token refresh works) instead of sharing the trusted user's
# full ~/.claude session data. If this exec fails (e.g. the sudo rule is missing), Claude does
# NOT launch -- fail closed, never as vscode.
#
# setpriv --no-new-privs (cont.25/26): `app` carries cap_add SETUID/SETGID/AUDIT_WRITE/CHOWN so
# this sudo can perform the drop at all (cap_drop: ALL alone empties the bounding set and sudo
# cannot setuid/setgid -- the cont.24 post-rebuild failure; CHOWN is what sudo's use_pty needs to
# chown the agent's pty in an interactive terminal -- cont.26). To keep the UNTRUSTED agent from abusing
# those caps via some setuid binary (su/mount/sudo) to climb back to euid 0 and setuid to the
# vscode uid, we set no_new_privs on the agent process the instant we land there: sudo (as
# vscode, with the caps) does the uid drop, then setpriv sets the irrevocable no_new_privs flag
# -- inherited by Claude and every Bash-tool child -- so no setuid bit can ever fire for agent.
# setpriv only lowers privilege, so it needs no caps of its own.
exec /usr/bin/sudo -u agent --preserve-env -- \
  /usr/bin/setpriv --no-new-privs \
  /usr/bin/env HOME=/home/agent TMPDIR=/home/agent/.tmp "$@"
