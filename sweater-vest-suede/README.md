# sweater-vest-suede

A Svelte 5 component testing library that renders tests alongside the components they test — in your running dev server, with no build step.

Tests are written as `.test.svelte` files. Each file contains one or more `<Sweater>` components. A `<Sweater>` pairs a **vest snippet** (the rendered component under test) with a **body function** (the async test logic). Tests run live in the browser and display their results in a dockview grid panel.

The same setup that powers interactive development also powers automated report generation: point the report script at your running dev server, and it drives a containerized browser through every test file and produces a Markdown report.

---

## Table of Contents

1. [Writing tests](#1-writing-tests)
2. [Vite setup](#2-vite-setup)
3. [SvelteKit setup](#3-sveltekit-setup)
4. [Automated reporting](#4-automated-reporting)
5. [Making reports informative](#5-making-reports-informative)

---

## 1. Writing tests

Place test files alongside the components they test (e.g. `Button.test.svelte` next to `Button.svelte`).

### Basic structure

```svelte
<!-- src/lib/Button.test.svelte -->
<script lang="ts">
  import { Sweater } from "<path>/sweater-vest-suede";
  import Button from "./Button.svelte";

  class Pocket {
    button = $state<HTMLButtonElement>();
    clicked = $state(false);
  }
</script>

<Sweater
  name="calls onClick when clicked"
  body={async (harness) => {
    const pocket = harness.set(new Pocket());
    const { button } = await harness.definition("button");

    await harness.withUserFocus(async (userEvent) => {
      await userEvent.click(button);
    });

    harness.expect(pocket.clicked).toBe(true);
  }}
>
  {#snippet vest(p: Pocket)}
    <Button bind:el={p.button} onclick={() => (p.clicked = true)} />
  {/snippet}
</Sweater>
```

The **pocket** is a plain class instance that holds reactive state shared between the vest and the body. Because fields are declared with `$state`, the body can observe DOM updates reactively via `harness.definition()`.

### `<Sweater>` props

| Prop       | Type                                                  | Description                                                           |
| ---------- | ----------------------------------------------------- | --------------------------------------------------------------------- |
| `body`     | `(harness: TestHarness<T>) => Promise<void>`          | The test logic. Required.                                             |
| `vest`     | `Snippet<[pocket: T]>`                                | The rendered component under test. Required.                          |
| `name`     | `string`                                              | Display name shown in the panel tab and report. Strongly recommended. |
| `id`       | `string`                                              | Stable identifier for targeting a specific test when filtering.       |
| `mode`     | `"parallel" \| "serial"`                              | Scheduling relative to siblings. Default: `"parallel"`.               |
| `lazy`     | `boolean`                                             | Defer rendering until `harness.set()` is called.                      |
| `manual`   | `boolean`                                             | Wait for an external trigger before running.                          |
| `position` | `"above" \| "below" \| "left" \| "right" \| "within"` | Position relative to the previous panel in the grid.                  |

### `TestHarness` API

| Member                | Description                                                                                                                                                                                    |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `set(pocket)`         | Initialise or replace the pocket; triggers render if `lazy`.                                                                                                                                   |
| `definition(...keys)` | Wait for named pocket fields to become non-null (requires `$state` runes).                                                                                                                     |
| `expect`              | All `@storybook/test` matchers (`expect(x).toBe(...)`, `expect(x).toMatchObject(...)`, etc.).                                                                                                  |
| `withUserFocus(fn)`   | Serialise user interactions through a shared queue to prevent synthetic-event races.                                                                                                           |
| `capture(type)`       | Screenshot the vest container. `"png"` / `"jpeg"` / `"svg"` return `{ uri: Promise<string>, download(filename) }`; `"blob"` / `"canvas"` / `"pixelData"` return the raw html-to-image promise. |
| `note(text)`          | Add a text annotation to the report card. No-op during interactive development.                                                                                                                |
| `delay(amount)`       | Sleep for `{ seconds }`, `{ milliseconds }`, `{ minutes }`, or `{ frames }`.                                                                                                                   |
| `container`           | The raw `HTMLElement` wrapping the vest snippet.                                                                                                                                               |
| `preventRender()`     | Block render until the returned function is called. Must be called before any `await`.                                                                                                         |
| `onAbort(fn)`         | Register a teardown callback for when the test is aborted.                                                                                                                                     |

### Grouping tests

Wrap `<Sweater>` instances in `<Sweater config>` to group them in a shared panel column and control their layout:

```svelte
<!-- Two tests stacked vertically in the same column -->
<Sweater config orientation="vertical" category="Button">
  <Sweater name="default state" body={...}>{#snippet vest(p)}{/snippet}</Sweater>
  <Sweater name="hover state"   body={...}>{#snippet vest(p)}{/snippet}</Sweater>
</Sweater>
```

The `category` prop on a config group labels that group in the report and can be used as a filter target.

---

## 2. Vite setup

### 1. Copy the template entry point

Copy `templates/vite/template.ts` to your `src/` directory (rename it — e.g. `src/tests.ts`). Update the `<path>` placeholder to point at `sweater-vest-suede` and the glob pattern to match where your test files live:

```ts
// src/tests.ts
import { mount } from "svelte";
import Closet from "<path>/sweater-vest-suede/Closet.svelte";

const app = mount(Closet, {
  target: document.getElementById("app")!,
  props: {
    glob: import.meta.glob("/src/**/*.test.svelte"),
  },
});

export default app;
```

> **Note:** The glob pattern must start with `/`. Patterns without a leading slash are relative to the file and will not pick up tests in other directories.

### 2. Copy the HTML entry point

Copy `templates/vite/template.html` to your project root (rename it — e.g. `tests.html`). Update the `file` attribute to point to the entry point from step 1 (e.g. `src/tests.ts`).

### 3. Add the report script to `package.json`

```jsonc
{
  "scripts": {
    "dev": "vite",
    "report": "<path>/sweater-vest-suede/report.sh",
  },
}
```

`report.sh` requires [`tsx`](https://tsx.is) to be available. Install it if needed:

```sh
npm install --save-dev tsx
```

### 4. Browse tests interactively

```sh
npm run dev
# Navigate to http://localhost:<port>/tests
```

`Closet.svelte` renders a tree of all discovered test files. Click any entry to load and run its tests.

---

## 3. SvelteKit setup

### 1. Create a tests route

Create a `tests/` directory inside `src/routes/` and copy `templates/sveltekit/+page.svelte` into it. Update the `<path>` placeholder:

```svelte
<!-- src/routes/tests/+page.svelte -->
<script lang="ts">
  import Closet from "<path>/sweater-vest-suede/Closet.svelte";
</script>

<Closet glob={import.meta.glob("/src/lib/**/*.test.svelte")} />
```

The glob pattern controls which test files appear in the list. Adjust it to match your project's directory structure.

### 2. Exclude the route from production builds

Prefix your build command with `with-exclude-tests-routes-from-build.sh` from `templates/sveltekit/`:

```jsonc
{
  "scripts": {
    "build": "<path>/sweater-vest-suede/templates/sveltekit/with-exclude-tests-routes-from-build.sh vite build",
  },
}
```

This temporarily renames `+page.svelte` → `_page.svelte` for the duration of the build, then restores it. The tests route is excluded from the production bundle without touching your source files.

### 3. Browse tests interactively

```sh
npm run dev
# Navigate to http://localhost:<port>/tests
```

---

## 4. Automated reporting

The report script starts a containerized Playwright browser, drives it through every test file the Closet knows about, collects results, and writes a Markdown report. **Docker is required** — no browser needs to be installed locally.

### Running the report

```sh
# Terminal 1 — keep this running
npm run dev

# Terminal 2
npm run report
# → prints a summary to stdout
# → writes fashion-show.md
```

Open `fashion-show.md` to see the full report with pass/fail status, duration, error messages, and any screenshots or notes added during the test run.

### CLI flags

| Flag                    | Shorthand | Description                                             | Default                         |
| ----------------------- | --------- | ------------------------------------------------------- | ------------------------------- |
| `--server <url>`        | `-s`      | URL where your dev server is running.                   | `http://<devcontainer-ip>:5173` |
| `--closet <path>`       | `-c`      | Path on `server` where `Closet.svelte` is rendered.     | `/`                             |
| `--browser <name>`      | `-b`      | Browser to use. Repeatable for multi-browser runs.      | `chromium`                      |
| `--output <path>`       | `-o`      | Output path for the Markdown report. Pass `""` to skip. | `./fashion-show.md`             |
| `--component <pattern>` | `-m`      | Only open components whose path matches this regex.     | (all)                           |
| `--test <pattern>`      | `-t`      | Only run tests whose name or id matches this regex.     | (all)                           |

Patterns are case-insensitive regular expressions. Tests that don't match `--test` are recorded as `skipped` in the report rather than omitted entirely.

#### Examples

```sh
# Only components whose path contains "Button"
npm run report -- --component Button

# Only tests named "hover", across all components
npm run report -- --test hover

# Both: Button component, hover tests only
npm run report -- --component Button --test hover

# Run on Firefox instead of Chromium
npm run report -- --browser firefox

# Write to a custom path
npm run report -- --output ./reports/latest.md
```

### Programmatic API

```ts
import { generateReport } from "<path>/sweater-vest-suede/report";

const summary = await generateReport({
  server: "http://localhost:5173",
  browsers: ["chromium", "firefox", "webkit"],
  output: "./reports/latest.md",
  component: /Button/i, // optional regex filter
  test: /hover/i, // optional regex filter
});

console.log(summary?.passed, "passed,", summary?.failed, "failed");
```

`generateReport` returns a `Report.Result.Summary` with `total`, `passed`, `failed`, and `skipped` counts, or `undefined` if generation fails.

### Multi-browser

Passing multiple `--browser` flags (or the `browsers` array in the programmatic API) runs every test in each browser. Results are grouped by component and test, with a separate run entry per browser. Tests that fail in one browser but pass in others are immediately visible in the report.

### CI

The report script exits non-zero if any tests fail (or if report generation itself errors). Standard CI setup:

```sh
npm run dev &
# wait for dev server to be ready, then:
npm run report -- --server http://localhost:5173
```

If you need to specify the server URL explicitly (e.g. because the runner is not a devcontainer), pass `--server`. The Docker requirement still applies — ensure the CI runner has Docker available.

---

## 5. Making reports informative

### Captures

Call `harness.capture("png")` at any point in the test body to snapshot the vest container at that moment. Call it multiple times to capture a sequence of states.

```ts
body={async (harness) => {
  const pocket = harness.set(new Pocket());
  await harness.definition("el");

  harness.capture("png");  // before interaction

  await harness.withUserFocus(async (userEvent) => {
    await userEvent.click(pocket.button);
  });

  harness.capture("png");  // after interaction
  harness.expect(pocket.result).toBe("clicked");
}}
```

Captures are embedded directly in the Markdown report as data URIs. Supported types: `"png"`, `"jpeg"`, `"svg"`. You do not need to `await` the capture — the report script waits for all pending images before recording the result.

### Notes

Call `harness.note(text)` to add a free-form text annotation that appears in the report card alongside captures:

```ts
body={async (harness) => {
  harness.note("Initial render — no value set yet");

  const pocket = harness.set(new Pocket({ value: "hello" }));
  await harness.delay({ milliseconds: 50 });

  harness.note(`After 50 ms — value is "${pocket.value}"`);
  harness.capture("png");

  harness.expect(pocket.value).toBe("hello");
}}
```

`note()` is a no-op when running without a report server attached, so it never affects interactive development.

### Named tests

Always give tests a `name`. Without one, test cards in the report are labelled `(unnamed)` and the stdout summary cannot identify which tests failed.

```svelte
<Sweater name="renders placeholder when value is empty" body={…}>
```

Use `id` alongside `name` when you want a stable identifier that survives renaming (useful for correlating results across multiple report runs):

```svelte
<Sweater name="renders placeholder when value is empty" id="button-placeholder" body={…}>
```
