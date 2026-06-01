import { resolve } from "node:path";
import { container, image } from "../programmatic-docker-suede";
import { devcontainer } from "../programmatic-docker-suede/devcontainer.js";
import CommandStream, {
  type CompletedResult,
} from "../programmatic-docker-suede/CommandStream.js";
import defaults from "./defaults.js";

/**
 * Currently, `chrome` is not supported on Apple Silicon due to Playwright's bundled Chromium not supporting ARM64 Linux.
 * This is supposed to be fixed in Q2 2026: https://blog.google/chromium/bringing-chrome-to-arm64-linux-devices/
 */
export const browsers = [
  "chromium",
  "firefox",
  "webkit",
  /** chrome */
] as const;
export type Browser = (typeof browsers)[number];

const __dirname = resolve(import.meta.dirname);
const context = resolve(__dirname, "docker");

type Options = Partial<
  typeof defaults & {
    onBuild: (stream: CommandStream) => void;
    log: boolean;
    network: string;
    skipIfRunning?: boolean;
  }
>;

/**
 *
 * @param BROWSER
 * @param details
 * @returns
 * @throws
 */
export const buildAndRun = async (BROWSER: Browser, details?: Options) => {
  const name = (details?.container ?? defaults.container)(BROWSER);

  if (details?.skipIfRunning && (await container.isRunning(name))) {
    if (details?.log)
      console.log(
        `Reusing existing running container for ${BROWSER} (${name})`,
      );
    // container.resolve returns a Dockerode.Container handle for an existing container,
    // matching the return type of container.run below.
    return container.resolve(name);
  }

  const tag = (details?.image ?? defaults.image)(BROWSER);

  if (details?.log)
    console.log(`(Try) Removing existing container for ${BROWSER}`);
  await container.tryRemove(name);

  if (details?.log) console.log(`Building image ${tag} from ${context}...`);

  const build = await image.build(tag, context, { buildargs: { BROWSER } });

  details?.onBuild?.(build);

  if (details?.log)
    for await (const chunk of build.chunks())
      process[chunk.kind === "err" ? "stderr" : "stdout"].write(chunk.data);

  const { exit, err } = await build.complete();

  if (exit !== 0)
    throw new Error(`Build failed for ${tag} with error:\n${err}`);

  const network = details?.network ?? (await devcontainer.network());

  const command = details?.command ?? defaults.command;
  return container.run({ network, name, command, image: tag });
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

type PlaywrightCliOptions = {
  session?: string;
  /** output response as JSON */
  json?: boolean;
  /** output only the result value, without status and code */
  raw?: boolean;
};

export const playwright = {
  args: (args: string[], options?: PlaywrightCliOptions) => [
    "playwright-cli",
    ...(options?.session ? [`-s=${options.session}`] : []),
    ...(options?.json ? ["--json"] : []),
    ...(options?.raw ? ["--raw"] : []),
    ...args,
  ],
  exec: (name: string, args: string[], options?: PlaywrightCliOptions) =>
    container.exec(name, playwright.args(args, options)),
  /** CLI does not return non-zero exit codes on error */
  errored: async (stream: CommandStream) => {
    const { out } = await stream.complete();
    return out.startsWith("### Error\n");
  },
  run: async (
    container: string,
    args: string[],
    options?: PlaywrightCliOptions,
  ) => {
    const result = await playwright.exec(container, args, options).complete();

    if (result.exit !== 0)
      throw new Error(`playwright-cli ${args[0]} failed: ${result.err}`);

    return result;
  },
  json: async <T>(
    container: string,
    args: string[],
    options?: Omit<PlaywrightCliOptions, "json">,
  ) => {
    const result = await playwright.run(container, args, {
      ...options,
      json: true,
    });
    return result.out.trim() ? (JSON.parse(result.out) as T) : undefined;
  },
  open: (
    container: string,
    browser: Browser,
    session: string,
    url: string = "about:blank",
  ) =>
    playwright.run(container, ["open", url, "--browser", browser], { session }),
  close: (container: string, session: string) =>
    playwright.run(container, ["close"], { session }),
  list: (container: string) =>
    playwright
      .json<{ browsers: Array<Record<string, unknown>> }>(container, ["list"])
      .then((result) => result?.browsers ?? []),
  ready: async (
    name: string,
    maxAttempts: number = 20,
    delayMs: number = 250,
  ): Promise<void> => {
    for (let i = 0; i < maxAttempts; i++) {
      if (await container.isRunning(name))
        if (await playwright.json(name, ["list"])) return;
      await sleep(delayMs);
    }
    throw new Error(`Playwright CLI not ready in container ${name}`);
  },
  parseCurrentTab: ({ out }: CompletedResult) => {
    const match = out.match(/^- (\d+):\s*\(current\)/m);
    if (match) return parseInt(match[1], 10);
    throw new Error(
      `Failed to get current tab index from output after creating tab:\n${out}`,
    );
  },

  newTab: async (
    container: string,
    url: string = "about:blank",
    session?: string,
  ) =>
    playwright
      .run(container, ["tab-new", url], { session, raw: true })
      .then(playwright.parseCurrentTab),

  selectTab: async (container: string, index: number, session?: string) => {
    const result = playwright.parseCurrentTab(
      await playwright.run(container, ["tab-select", index.toString()], {
        session,
        raw: true,
      }),
    );
    if (result !== index)
      throw new Error(
        `Failed to select tab ${index}, current tab is ${result}`,
      );
  },

  console: async (container: string, session?: string) =>
    playwright
      .run(container, ["console"], { session, raw: true })
      .then(({ out }) => out),

  evaluate: async <Return>(
    container: string,
    fn: () => Return,
    session?: string,
  ) =>
    playwright
      .run(container, ["eval", fn.toString()], { session, raw: true })
      .then(({ out }) =>
        out && out.trim() !== "undefined"
          ? (JSON.parse(out.trim()) as Return)
          : undefined,
      ),
};

export const sessionWithTabs = async (
  container: string,
  session: string,
  browser: Browser,
) => {
  await playwright.open(container, browser, session);

  const selectTab = (index: number) =>
    playwright.selectTab(container, index, session);

  const queue = {
    new: Promise.resolve(),
    select: Promise.resolve(),
  };

  /**
   * No-op used to advance the tail of a promise chain,
   * regardless of success/failure so it never stalls.
   */
  const advance = () => {};

  const withTabSelected = <Return>(index: number, fn: () => Return) => {
    const result = queue.select.then(async () => {
      await selectTab(index);
      return fn();
    }) as Promise<Awaited<Return>>;
    queue.select = result.then(advance, advance);
    return result;
  };

  return {
    selectTab,
    withTabSelected,
    newTab: (url: string = "about:blank") => {
      const result = queue.new.then(() =>
        playwright.newTab(container, url, session),
      );
      queue.new = result.then(advance, advance);
      return result;
    },
    evaluateOnTab: <Return>(index: number, fn: () => Return) =>
      withTabSelected(index, () =>
        playwright.evaluate<Return>(container, fn, session),
      ),
    consoleForTab: (index: number) =>
      withTabSelected(index, () => playwright.console(container, session)),
  };
};

export type SessionWithTabs = Awaited<ReturnType<typeof sessionWithTabs>>;

export const readFile = (name: string, path: string) =>
  container.exec(name, ["cat", path]).complete({ out: "buffer" });
