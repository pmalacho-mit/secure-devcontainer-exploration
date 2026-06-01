# secure-devcontainer-exploration

This dev container lets code — including coding agents — build, run, and `docker exec` sibling containers on the host Docker daemon, while preventing (or at least attempting to) those containers from gaining more privilege than the dev container itself, or being used to escape to the host. It's a two-layer gate in front of the Docker socket: a maintained endpoint-level proxy that holds the real socket ([tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy), plus a small custom body-inspecting shim that enforces a per-request "same access, or less" policy.

## Adapted from

The structure and hardening are adapted from Daniel Demmel's [*Coding agents in secured VS Code dev containers*](https://www.danieldemmel.me/blog/coding-agents-in-secured-vscode-dev-containers). Taken directly:

- The **threat model** — limit the blast radius of untrusted code: supply-chain attacks (malicious `npm` packages), prompt injection, and plain agent mistakes.
- The **compose-based dev container with a Docker socket proxy sidecar** ([tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)), where the app reaches Docker only through `DOCKER_HOST`.
- The **privilege hardening**: no `sudo` in the image, `cap_drop: ALL`, and `no-new-privileges: true`.
- The recognition that some risks (network egress, workspace writes) are **accepted** because development needs them.

## Where it differs — and why

The reference runs the socket proxy **read-only** (`POST`, `EXEC`, `BUILD` all off): the agent can inspect containers and read logs, but can't create, exec, or build. That's the right call when the agent only needs to *observe* Docker. 

My projects' workflows can **_not_** live with that, as they freely re-build and run containers, and in the case of a browser-testing image, rely on `exec`ing (using `playwright-cli` inside the container). So rather than *removing* those capabilities, it *constrains* them:

1. **Create is allowed but bounded.** tecnativa can only gate whole endpoints ("may you create containers at all?"), never request contents. So a body-inspecting shim sits in front of it, parses each `POST /containers/create`, and rejects anything that would grant a sibling more than the dev container has: privileged, added capabilities, devices, host or cross-container namespaces, host bind mounts outside the workspace, or weakened seccomp/apparmor. Container creation becomes a bounded operation instead of an escape primitive.

2. **Exec is label-gated, not blocked.** The reference blocks `docker exec` and routes interaction over HTTP instead. This project needs exec — but enabling it naively would let code `docker exec` into the *proxy* container (which holds the real socket) and escape. So the shim stamps an ownership label on every container it creates and permits exec **only** into labelled containers: your own test containers, never the proxy or anything else on the host.

3. **The proxy is network-isolated from created siblings.** Because creates are allowed, the design also has to stop those siblings from reaching the privileged proxy: the app and the proxy live on separate networks bridged only by the shim, and the shim rejects any create that tries to join the proxy network or share namespaces.

4. **Fail closed on unparseable bodies.** Any create whose body the shim can't parse is denied — which also avoids the class of authz bypass where a request reaches the policy without its body.

In short: the reference removes dangerous capabilities for an agent that only needs to read Docker; this project keeps the capabilities it genuinely needs and instead constrains them, preserving the invariant that siblings never exceed the dev container and can't reach the privileged layer.

### Not (yet) adopted

In the interest of honesty: the reference also hardens **VS Code's injected IPC sockets and env vars** (`VSCODE_IPC_HOOK_CLI`, `GIT_ASKPASS`, `BROWSER`, etc.), which are a separate container-escape surface. This setup does **not** include that — it's complementary and can be lifted from the blog directly. It also intentionally diverges on **SSH keys**: the reference doesn't mount them at all, whereas this project keeps them available (and monitored separately) rather than removed.
