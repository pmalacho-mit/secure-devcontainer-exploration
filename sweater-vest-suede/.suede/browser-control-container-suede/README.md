# Browser Control

This package ships a Docker image with Playwright installed and `playwright-cli`
available on `PATH` inside the container.

The preferred integration is the TypeScript API in `index.ts`, which builds and
runs the container for a selected browser.

## Preferred Usage

```ts
import { buildAndRun } from "./release/index.js"; // or use .ts extension if not using a bundler

await buildAndRun("chromium");
```

Supported browsers:

- `chromium`
- `firefox`
- `webkit`

The container is started with `tail -f /dev/null`, so you can execute commands
into it after startup.

## CLI Usage

Build the image directly:

```bash
docker build --build-arg BROWSER=chromium -t browser-control-chromium:latest .
docker run -d --rm --name browser-control-chromium browser-control-chromium:latest
docker exec browser-control-chromium playwright-cli --help
```

Because `/app/node_modules/.bin` is on `PATH`, `playwright-cli` is available
without a full path.
