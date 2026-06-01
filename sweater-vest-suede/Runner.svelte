<script lang="ts" module>
  import * as test from "@storybook/test";
  import { defer, accumulate } from "./utils";
  import type { createCapturer } from "./utils/capture";
  import { PromiseQueue } from "./utils/promise-queue";
  import until from "./utils/until";
  import { createTestAbortMechanism, TestAborted } from "./utils/abort";
  import { flushSync, type Snippet } from "svelte";
  import type { Props as ContainerProps } from "./Container.svelte";

  export type Pocket = Record<string, any>;

  type DelayKey = "seconds" | "milliseconds" | "minutes" | "frames";
  type Delay = {
    [K in DelayKey]: { [P in K]: number };
  }[DelayKey];

  /* pd: harness-docs */
  export type TestHarness<Pocket extends Record<string, any>> = {
    /**
     * Sets the pocket instance passed to the vest snippet.
     * Returns the pocket for convenience.
     */
    set: (pocket: Pocket) => Pocket;
    /**
     * The container element holding the rendered vest snippet.
     */
    container: HTMLElement;
    /**
     * Prevents rendering until the returned function is called.
     * Invoke before any `await` within test body to prevent initial render.
     */
    preventRender: () => () => void;
    /**
     * Registers a callback to run when the test is aborted.
     */
    onAbort: (fn: (this: AbortSignal) => void) => void;
    /**
     * Utilities for capturing the visual state of the `container` element.
     * @returns `{ toPng(), toSvg(), toJpeg(), toBlob(), toCanvas(), toPixelData() }`
     */
    capture: ReturnType<typeof createCapturer>;
    /**
     * Utility for awaiting a specified amount of time.
     * @example await harness.delay({ seconds: 2 });
     */
    delay: (amount: Delay) => Promise<void>;
    /**
     * Waits for specified `Pocket` fields to be defined (not null/undefined).
     * **NOTE:** fields must be `$state` runes to work correctly.
     * @example const { a, b } = await harness.definition("a", "b");
     */
    definition: <Keys extends keyof Pocket>(
      ...keys: Keys[]
    ) => Promise<{ [K in Keys]: NonNullable<Pocket[K]> }>;
    /**
     * Queues user interactions to run serially with access to userEvent.
     * @example await harness.withUserFocus(async (userEvent) => {
     *            await userEvent.click(button);
     *          });
     * This should be used in place of `import("@storybook/test").userEvent`.
     */
    withUserFocus: (
      fn: (userEvent: typeof test.userEvent) => Promise<void>,
    ) => Promise<void>;
    /**
     * Adds a free-form text annotation to this test's report card.
     * Call it at any point in the test body to label a state transition or
     * record a measurement. Annotations appear in call order in the report.
     * No-op when not running under a report server.
     */
    note: (text: string) => void;
  } & Omit<typeof import("@storybook/test"), "userEvent">;
  /* pd: harness-docs */

  type Mode = Required<PromiseQueue>["Types"]["Task"]["mode"];

  export type Props<T extends Pocket = Pocket> = {
    /**
     * The snippet rendered as the visual output of this test.
     * Receives the current `pocket` instance as its only argument.
     */
    vest: Snippet<[pocket: T]>;
    /**
     * The async test body. Receives a `harness` with utilities for
     * setting up state, interacting with the DOM, and making assertions.
     * @example
     * body={async ({ set, expect, container }) => {
     *   set(new Pocket(...));
     *   expect(container.querySelector("input")).not.toBeNull();
     * }}
     */
    body: (harness: TestHarness<T>) => Promise<void>;
    /**
     * Display name for this test.
     */
    name?: string;
    /**
     * Stable identifier for this test. Useful for targeting a specific
     * test when the file contains many.
     */
    id?: string;
    /**
     * Controls how this test is scheduled relative to others in its group.
     * - `"parallel"` (default) — runs concurrently with other parallel tests.
     * - `"serial"` — waits for all preceding tests to complete before starting.
     */
    mode?: Mode;
    /**
     * When `true`, the test will not start automatically — it must be
     * triggered manually (e.g. via a UI button). Defaults to `false`.
     */
    manual?: boolean;
    /**
     * When `true`, `pocket` is initialized as `undefined` and the `vest`
     * snippet will not render until `harness.set()` is called.
     * Use this when the pocket needs to be constructed asynchronously
     * before the component mounts.
     * @example
     * <Sweater lazy body={async (harness) => {
     *   const data = await fetchSomething();
     *   harness.set(new Pocket(data)); // vest then renders here
     *   // NOTE: `set` internally calls `svelte.flushSync` to force UI updates before continuing with test body
     * }}>
     */
    lazy?: boolean;
    /**
     * Controls where this test panel is positioned relative to its siblings
     * in the grid layout.
     * - `"above"` | `"below"` | `"left"` | `"right"` — docks beside a sibling.
     * - `"within"` — stacks inside the same panel as a sibling (tabbed).
     */
    position?: "above" | "below" | "left" | "right" | "within";
  };

  type Abort = () => void;
  type Complete = () => void;
  type Begin = (abort: Abort) => Complete;

  export type Container = Pick<ContainerProps, "category"> & {
    index: number;
  };

  export const reset = () => {
    queue = new PromiseQueue();
    console.log("reset");
  };

  let queue: PromiseQueue;

  const userFocusQueue = new PromiseQueue().open();
  const withUserFocus = (
    fn: (userEvent: typeof test.userEvent) => Promise<void>,
  ) => userFocusQueue.add("serial", () => fn(test.userEvent)).complete;

  const delay = async (amount: Delay): Promise<void> => {
    if ("frames" in amount) {
      let { frames } = amount;
      while (frames--) await until.nextFrame();
      return;
    }
    return until.milliseconds(
      "milliseconds" in amount
        ? amount.milliseconds
        : "seconds" in amount
          ? amount.seconds * 1000
          : "minutes" in amount
            ? amount.minutes * 60 * 1000
            : 0,
    );
  };

  const defined = <T,>(value: T | undefined | null): value is T =>
    value !== undefined && value !== null;

  const subscribeToDefinition = <T extends Pocket, K extends keyof T>(
    pocket: T,
    key: K,
    cleanup: Set<() => void>,
  ) => {
    const deferred = defer<Required<T>[K]>();
    const unsubscribe = $effect.root(() => {
      $effect(() => {
        const value = pocket[key];
        if (!defined(value)) return;
        unsubscribe();
        cleanup.delete(unsubscribe);
        deferred.resolve(value);
      });
    });
    cleanup.add(unsubscribe);
    return deferred.promise;
  };

  const error = (e: any) => {
    console.group("❌ Test Failed");
    console.error("Error:", e);
    console.error("Message:", e?.message);
    console.error("Name:", e?.name);
    console.error("Stack:", e?.stack);
    if (e?.matcherResult) console.error("Matcher Result:", e.matcherResult);
    console.groupEnd();
  };
</script>

<script lang="ts" generics="T extends Pocket">
  import { onMount } from "svelte";
  import { reportables } from "./report/client";

  let {
    body,
    vest,
    mode = "parallel",
    manual = false,
    lazy = false,
    begin,
    ...signature
  }: Props<T> & {
    index: number;
    container: Container;
    begin: Begin;
  } = $props();

  let container = $state.raw<HTMLDivElement>();
  let gate = $state.raw<Promise<any>>();
  let pocket = $state(lazy ? undefined : ({} as T));
  let prevented = $state(manual);

  /* svelte-ignore non_reactive_update */
  let rendered = false;

  type Harness = TestHarness<T>;

  const abort = createTestAbortMechanism();

  const set = abort.wrap(((payload) => {
    pocket = payload;
    if (lazy) flushSync();
    return pocket;
  }) satisfies Harness["set"]);

  const definition = abort.wrap((async (...keys) => {
    if (!pocket)
      throw new Error(
        "Pocket is not initialized. When using `lazy`, make sure to call `harness.set()` before accessing `harness.definition()`.",
      );
    const cleanup = new Set<() => void>();

    const resolved = await Promise.race([
      Promise.all(
        keys.map((key) =>
          defined(pocket![key])
            ? Promise.resolve(pocket![key])
            : subscribeToDefinition(pocket!, key, cleanup),
        ),
      ),
      abort.until,
    ]);

    for (const unsubscribe of cleanup) unsubscribe();

    abort.tryError();

    if (Array.isArray(resolved)) return accumulate(keys, resolved);

    return void 0 as unknown as Exclude<typeof resolved, void>; // unreachable
  }) satisfies Harness["definition"]);

  const preventRender: Harness["preventRender"] = abort.wrap(() => {
    if (rendered) {
      const msg = `Render has already happened, so it cannot be prevented. 
Make sure to call \`harness.preventRender()\` at the top of your body function before anything is \`await\`ed.`;
      throw new Error(msg);
    }
    prevented = true;
    const render = abort.wrap(() => (prevented = false));
    return render;
  });

  const { controller, on: onAbort } = abort;

  onMount(async () => {
    if (!container) throw new Error("Container element not found");

    const { createCapturer, note, skip, complete, fail } = reportables();

    const harness: TestHarness<T> = abort.proxy({
      ...test,
      container,
      set,
      preventRender,
      onAbort,
      definition,
      withUserFocus,
      delay,
      note,
      capture: createCapturer(container),
    });

    const run = async () => {
      if (skip?.(signature)) return begin(() => {})(); // clear pending.abort without adding a live abort entry

      const startedAt = Date.now();
      const fulfill = complete?.bind(null, startedAt, signature);
      const reject = (e: any) => {
        if (e instanceof TestAborted) return;
        fail?.(startedAt, signature, e);
        error(e);
      };

      await body(harness)
        .then(fulfill, reject)
        .finally(begin(() => controller.abort("Test has been aborted")));
    };

    gate = queue.add(mode, run).start;
    queue.open();
  });
</script>

<div bind:this={container} style="height: 100%;" title={signature.name}>
  {#if container && gate}
    {#await gate then}
      {#if !prevented && (!lazy || pocket)}
        {@render vest(pocket!)}
        {void (rendered = true)}
      {/if}
    {/await}
  {/if}
</div>
