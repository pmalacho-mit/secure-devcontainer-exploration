import { defer, type Deferred } from "../utils";
import { createHttpListener } from "./server.js";

export namespace Event {
  export type Typed<T extends string = string, V = {}> = { type: T } & V;

  /**
   * Sent by Closet.svelte on mount when `?reportServer=` is present and no `?component=` is set.
   */
  export type GalleryReady = Typed<"closet-ready", { paths: string[] }>;

  /**
   * Sent by Sweater.svelte once all `<Sweater>` instances on the page have mounted.
   */
  export type SuiteReady = Typed<
    "suite-ready",
    { totalTests: number; component?: string }
  >;

  export type Artifact = { type: string; dataUri: string } | string;

  /**
   * Sent by Runner.svelte when a test body resolves or rejects.
   */
  export type TestComplete = Typed<
    "test-complete",
    {
      name?: string;
      id?: string;
      components?: string;
      index: number;
      container: {
        index: number;
        category?: string;
      };
      component: string;
      status: "passed" | "failed";
      durationMs: number;
      error?: { message: string; stack?: string; matcherResult?: unknown };
      artifacts: Artifact[];
    }
  >;

  /**
   * Sent by Runner.svelte when a test is skipped because its name did not match `testFilter`.
   */
  export type TestSkipped = Typed<
    "test-skipped",
    {
      name?: string;
      id?: string;
      index: number;
      container: { index: number; category?: string };
      component: string;
    }
  >;

  export type Any = GalleryReady | SuiteReady | TestComplete | TestSkipped;

  export type Type = Any["type"];

  export type Handler = (
    route: string,
    event: Event.Any,
    close: () => void,
  ) => void;
}

export type TestResult = Omit<Event.TestComplete, "type" | "status"> & {
  status: "passed" | "failed" | "skipped";
};

export const events = {
  is: (raw: unknown): raw is Event.Any =>
    raw !== null &&
    typeof raw === "object" &&
    "type" in raw &&
    typeof raw.type === "string" &&
    (raw.type === ("closet-ready" satisfies Event.Type) ||
      raw.type === ("suite-ready" satisfies Event.Type) ||
      raw.type === ("test-complete" satisfies Event.Type) ||
      raw.type === ("test-skipped" satisfies Event.Type)),
  /** Returns a typed `ReportEvent` if `raw` has a known `type` discriminant, otherwise `undefined`. */
  parse: (raw: unknown): Event.Any | undefined =>
    events.is(raw) ? raw : undefined,
  toResult: (event: Event.TestComplete | Event.TestSkipped): TestResult =>
    event.type === "test-complete"
      ? event
      : {
          ...event,
          status: "skipped",
          durationMs: 0,
          artifacts: [],
        },
};

export const createEventListener = ({
  onEvent,
  timeout,
  onTimeout,
}: {
  onEvent: Event.Handler;
  timeout: number;
  onTimeout: () => void;
}) =>
  createHttpListener({
    timeout,
    onTimeout,
    onMessage: async ({ route, body, close }) => {
      const event = await events.parse(body);
      if (event) onEvent(route, event, close);
    },
  });

export type ReportServer = {
  /** Base URL of the server. */
  url: string;
  /** Resolves with the full list of component paths when the first `closet-ready` event arrives. */
  paths: Promise<string[]>;
  /**
   * Returns a promise that resolves with all test results for a given (browser, componentPath) pair
   * once the expected number of results (from `suite-ready`) have been received.
   * Safe to call before or after events arrive.
   */
  waitForComponent: (browser: string, path: string) => Promise<TestResult[]>;
  /** Stops the server and rejects any still-pending `paths` and `waitForComponent` promises. */
  close: () => void;
};

/**
 * A single server that handles discovery and all browser×component test events
 * for a full multi-browser report run. Used by `generateReport` in production.
 *
 * Routing:
 *   POST /discover        ← `closet-ready` from Closet.svelte (any browser)
 *   POST /<browser>       ← `suite-ready` / `test-complete` / `test-skipped` events;
 *                           browser is identified by the URL path, component by the
 *                           `component` field in the event body.
 *
 * @returns
 *   `url`              — base URL; append `/discover` or `/<browser>` to build
 *                        the `?reportServer=` query parameter.
 *   `paths`            — resolves on the first `gallery-ready` event (all browsers
 *                        share the same glob, so duplicates are ignored).
 *   `waitForComponent` — promise per (browser, componentPath) pair; safe to call
 *                        before or after events arrive.
 *   `close`            — stops the server and rejects any still-pending promises.
 */
export const startReportServer = async (
  timeout = 120_000,
): Promise<ReportServer> => {
  let discovered = false;
  const paths = defer<string[]>();

  type ComponentState = Deferred<TestResult[]> & {
    total: number | undefined;
    results: TestResult[];
  };
  const components = new Map<string, ComponentState>();

  const state = (browser: string, component: string) => {
    const key = `${browser}::${component}`;
    if (!components.has(key))
      components.set(key, {
        ...defer<TestResult[]>(),
        total: undefined,
        results: [],
      });
    return components.get(key)!;
  };

  const checkComplete = (browser: string, component: string) => {
    const state = components.get(`${browser}::${component}`);
    if (!state) return;
    if (state.total !== undefined && state.results.length >= state.total)
      state.resolve([...state.results]);
  };

  const discover = (event: Event.Any) => {
    if (discovered || event.type !== "closet-ready") return;
    discovered = true;
    paths.resolve(event.paths);
  };

  const onEvent: Event.Handler = (route, event) => {
    if (route === "discover") return discover(event);
    if (event.type === "closet-ready") return;

    const { type, component } = event;

    if (!component)
      return console.warn(
        `[sweater-vest] Received ${type} event with no component field — ignoring.`,
      );

    const browser = route;

    if (type === "suite-ready")
      state(browser, component).total = event.totalTests;
    else if (type === "test-complete" || type === "test-skipped")
      state(browser, component).results.push(events.toResult(event));

    checkComplete(browser, component);
  };

  const { url, close } = await createEventListener({
    onEvent,
    timeout,
    onTimeout: () => {
      const err = new Error("Report server timed out");
      if (!discovered) paths.reject(err);
      for (const state of components.values()) state.reject(err);
    },
  });

  return {
    url,
    paths: paths.promise,
    close: () => {
      close();
      const err = new Error("Report server closed");
      if (!discovered) paths.reject(err);
      for (const state of components.values()) state.reject(err);
    },
    waitForComponent: (browser, component) => state(browser, component).promise,
  };
};
