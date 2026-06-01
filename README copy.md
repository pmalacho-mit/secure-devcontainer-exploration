# Gated Docker dev container

A VS Code dev container that can build, run, and `docker exec` sibling containers
on the host daemon -- but through a gate that prevents those containers from having
*more* access than the dev container itself, and prevents them from being used to
escape to the host.

## How it works

```
  app (your dev container, DOCKER_HOST=tcp://docker-authz:2375)
    -> docker-authz          body-inspecting shim (this repo's authz-proxy.py)
       -> docker-endpoint-proxy   tecnativa/docker-socket-proxy (coarse endpoint ACL)
          -> /var/run/docker.sock the real socket (only this container can see it)
```

Two layers, each covering what the other can't:

- **tecnativa/docker-socket-proxy** holds the real socket and filters by *endpoint
  category* (it's the proven, maintained component). It allows only the categories
  you need and blocks the rest (`SWARM`, `SECRETS`, etc.).
- **authz-proxy.py** is a tiny shim that filters by *request body* -- the part
  tecnativa can't do. It inspects `POST /containers/create` and rejects anything
  that would grant a sibling more access than the dev container:
  privileged, added capabilities, devices, host/cross-container namespaces, host
  bind mounts outside the workspace, weakened seccomp/apparmor, or attaching to the
  proxy network. It stamps every container it creates with a label and allows
  `docker exec` **only** into labelled containers -- so you can exec your own
  containers, but not the privileged proxy or anything else on the host.

The networks are split so the dev container's only path to Docker is through the
shim: `app` is on `dev-net`, tecnativa is on `gate-proxy-net`, and the shim bridges
both. A sibling can't reach tecnativa directly (it's blocked from joining the gate
network), and the real socket is mounted only into tecnativa.

## Setup

1. Copy `.devcontainer/` (and optionally `test-escape.sh`) into your repo.
2. Open the folder in VS Code and "Reopen in Container" (or run via the devcontainer CLI).
   `initializeCommand` writes `.devcontainer/.env` with your workspace's host path so
   the shim can allow that path -- and only that path -- as a bind-mount source.
3. From inside the container, `docker` already points at the gate (`DOCKER_HOST`).

The tecnativa flags are set for a build + run + exec workflow (`BUILD`, `SESSION`,
`EXEC`, `CONTAINERS`, `IMAGES`, `NETWORKS`, `VOLUMES`, `POST` on; everything else off).
Turn off anything you don't use.

## Testing it

From inside the dev container:

```bash
./test-escape.sh
```

It attempts privileged runs, host mounts, socket mounts, host-PID, cap-add,
unconfined seccomp, joining the proxy network, and exec-into-the-proxy -- all of
which should be **blocked** -- plus a plain run and `docker ps`, which should be
**allowed**. Watch the decisions live from the host with:

```bash
docker compose -f .devcontainer/docker-compose.yml logs -f docker-authz
```

## Scope / honest limitations

- This gates the **Docker socket** escape vector. It enforces "a sibling gets the
  same access or less," not "a sibling can do no harm." A sibling still has network
  egress and can write the shared workspace -- because the dev container already can.
- `build` is allowed but **not** body-inspected (its body is a tar context, not JSON).
  Builds run unprivileged by default, and a built image is still subject to the run
  policy when started.
- The shim is the trusted component for body-level decisions; keep it minimal
  (it's standard-library only on purpose). tecnativa holds the real socket.
- Interactive `docker exec -it` / `attach` use HTTP hijacking and won't stream
  through the simple shim; non-interactive exec, `run`, `logs`, `ps`, `pull` work.
- It does **not** address other dev-container escape surfaces (e.g. VS Code's
  injected IPC sockets / `code` CLI). Harden those separately if relevant.
- Designed/tested against Docker Desktop on macOS (Apple Virtualization backend).
  If tecnativa can't read the socket, drop any `cap_drop` from that service and/or
  add `privileged: true` per its docs.
