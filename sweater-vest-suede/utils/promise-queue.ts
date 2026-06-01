import { type Deferred, defer } from ".";

export class PromiseQueue {
  Types?: {
    Task: Record<"start" | "complete", Promise<any>> & {
      mode: "serial" | "parallel";
    };
  };

  private readonly root: Deferred<void>;
  private tail?: Required<PromiseQueue>["Types"]["Task"];

  constructor() {
    this.root = defer();
  }

  open() {
    this.root.resolve();
    return this;
  }

  add(
    mode: Required<PromiseQueue>["Types"]["Task"]["mode"],
    fn: () => Promise<any>,
  ) {
    let task: Required<PromiseQueue>["Types"]["Task"];

    if (!this.tail) {
      const start = this.root.promise;
      task = { mode, start, complete: start.then(fn) };
    } else if (mode === "serial") {
      const start = this.tail.complete;
      task = { mode, start, complete: start.then(fn) };
    } else if (this.tail.mode === "serial") {
      const start = this.tail.complete;
      task = { mode, start, complete: start.then(fn) };
    } else {
      const { start, complete } = this.tail;
      task = { mode, start, complete: Promise.all([complete, start.then(fn)]) };
    }

    task.complete.finally(() => {
      if (this.tail === task) this.tail = undefined;
    });

    this.tail = task;
    return task;
  }
}
