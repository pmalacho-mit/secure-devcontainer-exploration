# shellcheck shell=sh
# harden-vscode-ipc.sh -- scrub VS Code's host-bridge channels from the shell env.
#
# WHAT THIS DEFENDS. VS Code Remote-Containers hands the dev container several
# channels that reach the HOST: a forwarded host SSH agent (SSH_AUTH_SOCK), the
# dev-containers git-credential broker (REMOTE_CONTAINERS_IPC -> host runs the git
# credential helper), and the `code` editor IPC hook (VSCODE_IPC_HOOK_CLI). The
# Docker-socket gate does NOT cover any of these -- they are the "VS Code IPC /
# extension-host sockets" open vector in docs/DESIGN.md. This file removes them from
# every shell the agent spawns.
#
# WHAT THIS IS NOT. Defence-in-depth ONLY. It runs in-container at the agent's own
# privilege, so a same-privilege attacker can re-discover the sockets by globbing
# /tmp -- exactly the repo's own principle that in-container controls are defeatable
# (see the SSH-monitor thread in DESIGN). It blocks accidental leakage and naive
# prompt-injection, not a fully adversarial dependency. Crucially it does NOT touch
# the EXTENSION-HOST API path: any installed extension can call `vscode.workspace.fs`
# over a `vscode-local://` URI for an arbitrary host read AND write, over the extension
# host's own connection (which never used these env vars). The tamper-resistant
# controls are all HOST-side: (1) Workspace Trust + an ENFORCED extensions allowlist
# (`extensions.allowed`) in your host user settings, so only vetted extensions ever
# run; (2) disable SSH-agent / git-credential forwarding ("dev.containers.copyGitConfig":
# false; don't export SSH_AUTH_SOCK to the host session). See docs/DESIGN.md (cont. 13 +
# cont. 18, which documents the two-channel model and why this script is only half of it).

# --- host-reaching credential / agent channels (safe to drop: you only lose
#     forwarding, never editor integration) -----------------------------------
unset REMOTE_CONTAINERS_IPC REMOTE_CONTAINERS_SOCKETS GPG_AGENT_INFO 2>/dev/null || true
unset GIT_ASKPASS VSCODE_GIT_IPC_HANDLE VSCODE_GIT_ASKPASS_NODE \
      VSCODE_GIT_ASKPASS_MAIN VSCODE_GIT_ASKPASS_EXTRA_ARGS 2>/dev/null || true
SSH_AUTH_SOCK=
export SSH_AUTH_SOCK

# --- STRICTER (ENABLED as of cont. 18): also cut the `code` editor IPC hook + the
#     default browser. This closes the in-container half of the host-file read
#     confirmed live -- `code --file-uri "vscode-local:///Users/.../file"` opens an
#     arbitrary HOST file through the editor channel. Raises isolation, but breaks
#     `code` from the terminal and can degrade in-editor agent integration (diffs,
#     "open file", selection context). To RESTORE that integration, re-comment the two
#     lines below AND remove VSCODE_IPC_HOOK_CLI/BROWSER from devcontainer.json's
#     remoteEnv. NB: defeatable by re-globbing /tmp, and it does NOT touch the
#     extension-host API (`vscode.workspace.fs` over `vscode-local://`) -- the real
#     boundary is host-side (Workspace Trust + the enforced extensions allowlist).
unset VSCODE_IPC_HOOK_CLI 2>/dev/null || true
BROWSER=; export BROWSER
