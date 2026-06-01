import type { SearchParam, Event } from "./index.js";
import { createCapturer as rawCreateCapturer } from "../utils/capture.js";
import type { Props as RunnerProps, Container } from "../Runner.svelte";

export const param = (key: SearchParam, url?: URL) =>
  (url ?? new URL(window.location.href)).searchParams.get(key) ?? undefined;

export const server = (url?: URL) => param("reportServer", url);

export const tryPost = (event: Event.Any, url?: URL | string) => {
  const endpoint = url
    ? typeof url === "string"
      ? url
      : server(url)
    : undefined;
  if (!endpoint) return;
  fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  }).catch(() => {});
};

export const suiteReady = (totalTests: number) => {
  const url = new URL(window.location.href);
  tryPost(
    {
      type: "suite-ready",
      totalTests,
      component: param("component", url),
    },
    url,
  );
};

type TestSignature = Pick<RunnerProps, "name" | "id"> & {
  index: number;
  container: Container;
};

export const reportables = () => {
  const url = new URL(window.location.href);
  const endpoint = server(url);

  if (!endpoint)
    return {
      createCapturer: rawCreateCapturer,
      note: (_: string) => {}, // no-op
    };

  const pending = new Array<Promise<Event.Artifact>>();

  const createCapturer: typeof rawCreateCapturer = (container) => {
    const rawCapture = rawCreateCapturer(container);

    const reportable = (() => {
      type Type = Parameters<typeof rawCapture>[0];
      const reportable = ["png", "jpeg", "svg"] as const satisfies Type[];
      type Reportable = (typeof reportable)[number];
      type Captured<T extends Type = Type> = ReturnType<typeof rawCapture<T>>;
      return (type: Type, _: Captured): _ is Captured<Reportable> =>
        (reportable as Type[]).includes(type);
    })();

    return (type, options) => {
      const captured = rawCapture(type, options);
      if (reportable(type, captured))
        pending.push(captured.uri.then((dataUri) => ({ type, dataUri })));
      return captured;
    };
  };

  const note = (text: string) => pending.push(Promise.resolve(text));

  const component = param("component", url);

  if (!component)
    throw new Error(
      "Component name is required in the URL parameter when reportServer is specified",
    );

  const complete = async (startedAt: number, signature: TestSignature) =>
    tryPost(
      {
        ...signature,
        component,
        type: "test-complete",
        status: "passed",
        durationMs: Date.now() - startedAt,
        artifacts: await Promise.all(pending),
      },
      endpoint,
    );

  const fail = async (
    startedAt: number,
    signature: TestSignature,
    error?: any,
  ) =>
    tryPost(
      {
        ...signature,
        component,
        type: "test-complete",
        status: "failed",
        durationMs: Date.now() - startedAt,
        error: {
          message: error?.message,
          stack: error?.stack,
          matcherResult: error?.matcherResult,
        },
        artifacts: await Promise.all(pending),
      },
      endpoint,
    );

  const testFilterSource = param("testFilter", url);
  const testFilter = testFilterSource
    ? new RegExp(testFilterSource, "i")
    : undefined;

  const matches = (text: string | undefined) =>
    text && testFilter && testFilter.test(text);

  const skip = (signature: TestSignature) => {
    const { name, id, container } = signature;
    const skipped = matches(name ?? id) || matches(container.category);
    if (skipped)
      tryPost({ type: "test-skipped", component, ...signature }, endpoint);
    return Boolean(skipped);
  };

  return {
    createCapturer,
    note,
    complete,
    fail,
    /**
     * Returns `true` if the test with the given `name` or `id` should be skipped based on the `testFilter`
     */
    skip,
  };
};
