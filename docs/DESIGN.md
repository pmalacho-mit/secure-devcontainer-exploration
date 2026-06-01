# Project handoff: secured dev container with a Docker-socket authz gate

## TL;DR

This repo contains a VS Code dev container that can **build, run, and `docker exec` sibling containers** on the host Docker daemon, but routes all Docker access through a **two-layer gate** that enforces one invariant: *a sibling container can never have more access than the dev container itself, and can never reach the privileged layer to escape to the host.* The gate is **tecnativa/docker-socket-proxy** (holds the real socket, filters by endpoint) plus a **small custom Python shim** (`authz-proxy.py`, filters by request *body*). Networks are per-dev-container; the shim allow-stamps containers it creates and only lets you `exec` into those. A separate, earlier thread produced a **host-side (macOS) SSH-key-read monitor** that runs outside the container — keep that in mind but it's not part of this repo's runtime.

## How we got here (context and rejected paths)

The exploration started from "do dev containers improve dependency-install security?" The honest answer shaped everything after: a dev container **contains the blast radius** of install-time code execution (malicious `npm`/`pip` postinstall scripts run in the container, not on the host), but it does **not prevent** the attack, and its value collapses if you mount secrets, the Docker socket, or forward an agent into it. Two concrete exposures drove the work: bind-mounted SSH keys, and a bind-mounted Docker socket (`docker-outside-of-docker`).

**SSH-key monitoring thread (separate, host-side).** We wanted to detect when a container reads the bind-mounted private key. Key findings, in order of what got rejected and why:
- `inotify` can tell you a file was read but **not which process** — insufficient.
- `auditd`/`fatrace`/eBPF give process attribution but need elevated privilege and, on a Mac, don't apply the way they would on native Linux.
- On macOS + Docker Desktop, the container runs in a **Linux VM**; a host-side monitor sees the read attributed to the **VM file-sharing process** (`com.apple.Virtualization.*`), not the container or in-container process. You can't tell *which* container did it from the host.
- Any in-container monitor is defeatable by a **same-privilege attacker** (kill it, forge its heartbeat). The only tamper-resistant layer is **outside the container** — the host.
- VS Code extensions get **no elevated privilege** (workspace extensions run in the killable extension host); they don't help as a tamper-resistant monitor.

Final SSH monitor = a **macOS `fs_usage` script** (no Full Disk Access needed, unlike `eslogger`; no System Events automation grant) that filters to container reads (`com.apple.Virtualization`) of the private key and pops a **must-dismiss dialog**. It lives on the Mac host, not in this repo.

**Docker-socket thread (the main deliverable).** A bind-mounted socket is effectively host root, so it's the bigger exposure. We rejected:
- **Daemon-side authorization plugins (OPA `opa-docker-authz`)** — the "proper" tool, but **not viable on Docker Desktop**: the daemon is in the VM, the policy file can't easily be placed there, it's daemon-wide, and body-introspecting authz had a CVSS-10 bypass (CVE-2024-41110) where requests could reach the plugin without their body.
- **tecnativa alone** — it filters by endpoint category only; it cannot express "create, but only unprivileged and only mounting the workspace."

So we built a **userspace body-inspecting shim in front of tecnativa**, which is scoped to the dev container, runs identically on Mac/Linux, and reuses the proven proxy to hold the socket.

We also **inspected the actual workflow** (`pmalacho-mit/sweater-vest-suede`, `release/report/index.ts` + the `browser-control-container-suede` helper). It **builds** an image (`image.build` → `POST /build`), **runs** it plain/unprivileged on the dev container's network, and **drives it via `docker exec`** (`playwright-cli` — the entire control layer is exec). That's why `BUILD`, `SESSION`, and `EXEC` are enabled, and why exec needed special handling.

## Main points of consideration (the principles)

- **Containment, not prevention.** The goal is "siblings get the same access or less," and "can't reach the privileged layer," not "can do no harm."
- **Allowlist over denylist** for the create-body policy; the Docker create API is large, so deny by default on the dangerous fields.
- **Transitivity.** Allowing `create` means you must stop created siblings from reaching the privileged proxy (its network, the socket, shared namespaces) — or the invariant leaks.
- **Keep the trusted, socket-holding component maintained and minimal.** tecnativa holds the socket; the custom shim never touches it directly and handles the fewest endpoints possible.
- **Host-side is the only tamper-resistant monitoring layer** (the SSH thread's lesson).
- **Per-dev-container isolation** so multiple projects don't collide; identify the gate dynamically rather than by a fixed name.
- **Fail closed** — an unparseable create/inspect is denied.
- **Be honest about scope** — egress, workspace writes, VS Code IPC sockets, and build contents are *not* covered.

## Final design decisions

1. **Compose-based dev container, three services:** `docker-endpoint-proxy` (tecnativa), `docker-authz` (the shim), `app` (the dev container). The real socket is mounted **only** into tecnativa (`:ro`); `app` reaches Docker only via `DOCKER_HOST=tcp://docker-authz:2375`.
2. **tecnativa endpoint ACL:** `CONTAINERS, IMAGES, NETWORKS, VOLUMES, POST, BUILD, SESSION, EXEC = 1`; everything else `0`. (`BUILD`/`SESSION`/`EXEC` are on specifically because the workflow builds and execs.)
3. **Shim body policy (`authz-proxy.py`):**
   - `POST /containers/create` → deny `Privileged`, `CapAdd`, devices, `VolumesFrom`, host/cross-container namespaces, unconfined seccomp/apparmor, binds/mounts whose source is outside the workspace host path, and joining the gate network. Then **stamp an ownership label** (`authz.owned=1`) on the container.
   - `POST /containers/{id}/exec` → allowed **only** if the target carries the ownership label (so you can exec your own containers, never the proxy or anything else on the host).
   - Everything else passes through; anything unparseable is denied.
4. **Per-dev-container networks:** Compose networks are unnamed → project-scoped (`<project>_dev`, `<project>_gate`), so each dev container is isolated and the app keeps discovering its network programmatically. The shim identifies the **gate** network two ways — by Compose suffix (`…_gate`) and by **runtime discovery of its real name and id** (resolves the proxy's address, finds its network) — so an attacker can't join the gate by network *id* to slip past a name check.
5. **Privilege hardening:** `app` and `docker-authz` use `cap_drop: ALL`; `app` adds `no-new-privileges: true`; no `sudo` is added to the image.
6. **Workspace bind allowlist:** `initializeCommand` captures the host workspace path into `.devcontainer/.env`; the shim allows bind-mount sources only under that path.
7. **`test-escape.sh`** verifies the gate (privileged, host/socket mounts, `--pid=host`, cap-add, unconfined seccomp, joining the gate by name *and* id, exec-into-proxy → all blocked; plain run + `docker ps` → allowed).

## Update (2026-06-01): browser joins the dev network as a peer, not a shared netns

A discrepancy surfaced when the actual workflow (`sweater-vest-suede`) was checked against the gate. DESIGN said the browser image "runs plain on the dev container's network," but the code ran it with `--network container:<devcontainer-id>` — a shared **network namespace** (`devcontainer.network()` returned `container:<id>`). The shim rejects *all* cross-container namespaces, so the gate would have **blocked the workflow on its first `buildAndRun`**.

Two ways to reconcile were considered: (a) relax the gate to allow netns-sharing of non-gate targets, or (b) change the workflow to join the dev network as an ordinary **peer**. We chose **(b)** — it keeps the trusted shim strict and minimal (no netns sharing of any kind, the stated principle), and a peer is *strictly less* privileged than a netns share (a netns-sharing sibling could bind the dev container's own loopback/interfaces and impersonate its localhost services; a peer cannot). The reachability the workflow needs is identical: servers inside the dev container bind `0.0.0.0` and siblings reach them at `devcontainer.ip()` either way.

Change made: `sweater-vest-suede/.suede/programmatic-docker-suede/devcontainer.ts` — `devcontainer.network()` now returns the **name** of the dev container's attached (non-gate) network, so the browser runs with `--network <project>_dev`. No gate relaxation; the create policy still rejects `host` and every `container:`/`Pid`/`Ipc`/`Uts`/`Userns` namespace share. DESIGN's "runs on the dev container's network" is now literally true.

Also hardened in this pass:
- **`POST /networks/{id}/connect` is now gated.** Previously only *create*-time network joins were policed, so a sibling could be created plain (owned) and then wired onto the gate network after the fact, reaching tecnativa directly and bypassing the shim. The shim now denies connecting any container to a gate network — matched by suffix, by discovered name/id, **and** by live membership (`network_is_gate`, a backstop that inspects the target network for the proxy even if discovery hasn't cached it yet).
- **Eager gate discovery at startup.** The shim now resolves the gate network's real name+id on boot (retrying ~10s while the proxy comes up) so id-based joins are caught from the first request, and logs a prominent `WARNING` if discovery never succeeds (the previously silent degrade-to-suffix-only case).

**Known residuals / out of scope:** network egress and workspace writes are accepted (they equal the dev container's own access); `build` is allowed but not body-inspectable (trusted; runs unprivileged); VS Code IPC-socket escape vectors are not addressed; the gate's id-based block depends on runtime discovery succeeding (watch for a `discovered gate network: {...}` line, or the `WARNING` if it didn't — without discovery, only suffix-matching guards join-by-id); the simple shim forces `Connection: close`, so interactive `exec -it`/`attach` streaming won't pass through; SSH keys are bind-mounted and monitored separately rather than removed.

**Key files:** `.devcontainer/authz-proxy.py` (the policy), `.devcontainer/docker-compose.yml` (topology + tecnativa flags + networks), `.devcontainer/devcontainer.json` (`initializeCommand`), `README.md` (rationale), `test-escape.sh` (verification).

## Handoff / current state (2026-06-01) — for the next agent

**Status: code changes complete; runtime verification NOT yet run.** The agent that did this pass worked in a sandbox without `docker`/`node`/`python`, so only static verification was possible (`bash -n test-escape.sh` passes; full end-to-end read-through of the shim; hermetic policy test authored). The three runtime checks below still need to be run inside a rebuilt dev container — **start here.**

**Changes landed in this pass (all on the working tree, uncommitted):**
- `sweater-vest-suede/.suede/programmatic-docker-suede/devcontainer.ts` — `devcontainer.network()` returns the dev network **name** (peer), not `container:<id>` (netns). This is the change that makes the workflow compatible with the strict gate. (`sweater-vest-suede/` is an untracked sibling folder, not part of this repo's git history.)
- `.devcontainer/authz-proxy.py` — added (1) `POST /networks/{id}/connect` gating against the gate network (`CONNECT_RE`, `network_is_gate`), (2) eager gate discovery + `WARNING` at startup in `main()`. **No netns relaxation** — `host` and all `container:`/`Pid`/`Ipc`/`Uts`/`Userns` shares are still rejected.
- `.devcontainer/Dockerfile` — added `python3` (only so the gate's own tests run inside the container; does not touch the gate).
- `.devcontainer/test_policy.py` — NEW. Hermetic unit tests for `check_create` + `is_gate_net`, no daemon needed.
- `test-escape.sh` — added connect-to-gate denials (name+id) and a dev-net peer allow-case.
- `README.md` — peer model + connect-gating documented; fixed an unbalanced-paren typo.

**Live partial verification already done (against the OLD, still-running shim, via `curl` since the `docker` CLI was missing — see next note):** `GET /version` works through the full path (daemon 29.2.1); `POST /containers/create {Privileged:true}` → 403, `{NetworkMode:"container:abc"}` → 403 (the netns block that motivated the peer fix, confirmed live). The connect-to-gate probe returned **404, not 403**, proving the running `docker-authz` container is the **pre-edit** shim — so the connect-gating + eager discovery are NOT live yet. **Rebuild `docker-authz` (or the whole stack) to deploy the new shim**, then re-run the checks below.

**Docker CLI / base image (fixed in this pass):** the dev container had NO `docker` client even though `docker.io` was installed — on Debian 13 (trixie) `docker.io` ships the daemon only and the client was split out. `.devcontainer/Dockerfile` was switched to an **Ubuntu base** and now installs **`docker-ce-cli` (client only)** from Docker's official apt repo (plus `python3`). This needs a rebuild to take effect; until then, verify via `curl http://docker-authz:2375/...` as above. Note `sudo` does not work in the running container (`no-new-privileges` + `cap_drop: ALL`), so you can't install the client live — it must come from the image rebuild.

**Runtime verification to run next (inside the rebuilt dev container):**
```bash
python3 .devcontainer/test_policy.py     # 1. pure policy logic -> expect failed=0
./test-escape.sh                         # 2. full gate integration -> "the gate held."
# 3. workflow's Docker-API slice (no node): build/run-as-peer/exec
DEV=$(docker network ls --format '{{.Name}}' | grep -E '_dev$' | head -n1)
docker run -d --name probe --network "$DEV" alpine sleep 60 && docker exec probe echo ok && docker rm -f probe
```
After the stack is up, confirm the shim logged `discovered gate network: {...}` (and NOT the `WARNING`) — `docker compose -f .devcontainer/docker-compose.yml logs docker-authz`.

**Open / not done (deliberately):**
- Full report E2E (vite + `Closet.svelte` + the playwright browser image driven by `playwright-cli` over `docker exec`) was NOT run — it's a much larger lift than the gate-level checks. Optional follow-up once 1–3 are green.
- Chunked-`create` decoding was intentionally NOT added: dockerode always sends `Content-Length`, `/build` isn't body-inspected, and the existing fail-closed `deny` is safer than adding a parser to the trusted shim. Revisit only if a real client sends a chunked create.
- These changes are uncommitted; the next agent (or the user) should review `git diff` and commit when satisfied. Note the working tree also carries pre-existing uncommitted edits from before this pass (`docker-compose.yml`, a `README copy.md` deletion) — confirm those are intended before committing.