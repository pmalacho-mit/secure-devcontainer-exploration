# programmatic-docker-suede

Thin TypeScript wrappers around [Dockerode](https://github.com/apocas/dockerode) for building images, running containers, and streaming command output. Read the source — it's short.

## Exports

**[index.ts](index.ts)** — main entry point

- `docker(args)` — raw `docker` CLI escape hatch; `docker.verify()` pings the daemon
- `image` — `build(tag, context)`, `inspect(name)`, `remove(name)`
- `container` — `run(opts)`, `exec(c, args)`, `log(c)`, `inspect(c)`, `isRunning(c)`, `start(c)`, `remove(c)`
- `dockerode` — underlying Dockerode instance for advanced use
- `Container` namespace — `RunOptions`, `Instance`, `PublishedPort`, `MountedVolume` types

**[CommandStream.ts](CommandStream.ts)** — returned by `container.exec()` and `container.log()`

- `.complete()` — buffers all output; returns `{ out, err, exit }`. Never throws.
- `.chunks()` — async generator yielding `{ kind: "out"|"err", data }` as they arrive; call `.complete()` after to get the exit code

Both methods accept an optional encoding arg (`"string"` | `"buffer"` | `{ out?, err? }`).

**[devcontainer.ts](devcontainer.ts)** — devcontainer networking utilities

- `getDevcontainerId()` — detects the current devcontainer's container ID from hostname
- `getDevcontainerIp()` — returns the devcontainer's non-loopback IPv4 (needed because `127.0.0.1`-bound servers aren't reachable from a joined container)
- `devcontainerNetwork(id?)` — returns `"container:<id>"` for use as `network` in `container.run()`
