import type { Fn } from "./types";

export class TestAborted extends Error {
  constructor(message: string = "Test aborted") {
    super(message);
  }
}

export const onAbort = (signal: AbortSignal, fn: (this: AbortSignal) => void) =>
  signal.addEventListener("abort", fn, { once: true });

export const createTestAbortMechanism = () => {
  const controller = new AbortController();
  const { signal } = controller;

  const tryError = () => {
    if (signal.aborted) throw new TestAborted();
    return true;
  };

  const wrap =
    <T extends Fn>(fn: T) =>
    (...args: Parameters<T>) =>
      (tryError() && fn(...args)) as ReturnType<T>;

  const on = onAbort.bind(null, signal);

  const until = new Promise<void>(on);

  const proxy = <T extends object>(_target: T) =>
    new Proxy(_target, {
      get(target, prop) {
        return tryError() && target[prop as keyof T];
      },
      set(target, prop, value) {
        target[prop as keyof T] = value;
        return tryError();
      },
    });

  return { signal, tryError, wrap, until, controller, proxy, on };
};
