# secure-devcontainer-exploration

This dev container lets code — including coding agents — build, run, and `docker exec` sibling containers on the host Docker daemon, while preventing (or at least attempting to) those containers from gaining more privilege than the dev container itself, or being used to escape to the host. It's a two-layer gate in front of the Docker socket: a maintained endpoint-level proxy that holds the real socket ([tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)), plus a small custom body-inspecting shim that enforces a per-request "same access, or less" policy.

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

3. **The proxy is network-isolated from created siblings.** Because creates are allowed, the design also has to stop those siblings from reaching the privileged proxy: the app and the proxy live on separate networks bridged only by the shim, and the shim rejects any create that tries to join the proxy network or share namespaces — *and* any `docker network connect` that would wire an existing container onto the gate network after the fact. Siblings that need to reach servers inside the dev container (e.g. the browser image driving tests) join the dev container's network as ordinary **peers** (`--network <project>_dev`), never by sharing its network namespace — same reachability, strictly less privilege.

4. **Fail closed on unparseable bodies.** Any create whose body the shim can't parse is denied — which also avoids the class of authz bypass where a request reaches the policy without its body.

In short: the reference removes dangerous capabilities for an agent that only needs to read Docker; this project keeps the capabilities it genuinely needs and instead constrains them, preserving the invariant that siblings never exceed the dev container and can't reach the privileged layer.

### Per-devcontainer network isolation (and how the gate is identified)

Each dev container gets its **own** Docker networks rather than a shared, fixed-named pair. The Compose networks are left unnamed, so Compose scopes them to the project (`<project>_dev`, `<project>_gate`), and since the devcontainer CLI assigns each dev container a distinct project, two projects never collide on a network. The app keeps discovering its network programmatically (e.g. `devcontainer.network()`) instead of relying on a hard-coded name — which is the whole point of leaving them unnamed.

That makes the gate network's name *dynamic*, so the shim can't block it by a fixed string. It recognises the gate two ways:

- **By Compose suffix** — anything matching `…_gate` (any project's gate network), caught immediately with no lookup.
- **By discovered identity** — at runtime the shim resolves the proxy's address and finds which network it actually sits on, recording that network's real **name and id**. This closes the gap where an attacker enumerates networks, grabs the gate's **id**, and tries to join by hash to slip past a name-only check: joining the gate by id is rejected too.

Namespace sharing (`--pid`, `--ipc`, `--network container:…`, host namespaces) is rejected outright, since those are other routes a sibling could use to reach the proxy's process or network.

### Not (yet) adopted

In the interest of honesty: the reference also hardens **VS Code's injected IPC sockets and env vars** (`VSCODE_IPC_HOOK_CLI`, `GIT_ASKPASS`, `BROWSER`, etc.), which are a separate container-escape surface. This setup does **not** include that — it's complementary and can be lifted from the blog directly. It also intentionally diverges on **SSH keys**: the reference doesn't mount them at all, whereas this project keeps them available (and monitored separately) rather than removed.

## Trying it

From inside the dev container, `./test-escape.sh` attempts privileged runs, host/socket mounts, `--pid=host`, `--cap-add`, unconfined seccomp, joining the gate network **by name and by id**, wiring an existing container onto the gate with `docker network connect` (by name and id), and exec-into-the-proxy — all of which should be blocked — plus a plain run, joining the dev network as a peer, and `docker ps`, which should be allowed. Watch decisions stream from the host with `docker compose -f .devcontainer/docker-compose.yml logs -f docker-authz`.
