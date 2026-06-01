import { PassThrough } from "node:stream";
import type Dockerode from "dockerode";

type Encoding = "string" | "buffer";
type Encoded<E extends Encoding> = E extends "string" ? string : Buffer;
type ResolvedEncoding = { out?: Encoding; err?: Encoding };

const resolve = (
  encoding?: Encoding | ResolvedEncoding,
): Required<ResolvedEncoding> =>
  !encoding || encoding === "string"
    ? { out: "string", err: "string" }
    : encoding === "buffer"
      ? { out: "buffer", err: "buffer" }
      : { out: encoding.out ?? "string", err: encoding.err ?? "string" };

const encode = (buffer: Buffer, encoding: Encoding) =>
  encoding === "buffer" ? buffer : buffer.toString("utf-8");

export type CompletedResult<Out = string, Err = string> = {
  out: Out;
  err: Err;
} & ({ exit: 0 } | { exit: number; error?: Error });

export type Chunk<Out = string, Err = string> =
  | { kind: "out"; data: Out }
  | { kind: "err"; data: Err };

namespace Raw {
  export type Result = {
    stdout: Buffer;
    stderr: Buffer;
    exit: number;
    error?: Error;
  };
  export type Chunk = { kind: "out" | "err"; data: Buffer };
}

type StreamFactory = () => Promise<{
  stream: NodeJS.ReadableStream;
  getExitCode: () => Promise<number>;
  /** Skip demuxStream and pipe the stream directly to stdout (for non-multiplexed streams like image builds). */
  raw?: boolean;
}>;

/**
 * A lazy, single-use wrapper around a docker exec stream.
 *
 * Returned synchronously from `docker.exec()` — no work happens until
 * `.complete()` or `.chunks()` is called.
 *
 * @example
 * // Buffered — text (default)
 * const { stdout, exitCode } = await docker.exec(name, cmd).complete();
 *
 * // Buffered — raw binary
 * const { stdout } = await docker.exec(name, cmd).complete("buffer");
 *
 * // Buffered — mixed
 * const { stdout, stderr } = await docker.exec(name, cmd).complete({ out: "buffer", err: "string" });
 *
 * // Streaming, then exit code
 * const stream = docker.exec(name, cmd);
 * for await (const chunk of stream.chunks()) { ... }
 * const { exitCode } = await stream.complete();
 */
export default class CommandStream {
  #inprogress?: Promise<Raw.Result>;
  #queue: Array<Raw.Chunk | undefined> = [];
  #notify?: () => void;

  readonly factory: StreamFactory;
  readonly dockerode: Dockerode;

  constructor(dockerode: Dockerode, factory: StreamFactory) {
    this.factory = factory;
    this.dockerode = dockerode;
  }

  #open(): Promise<Raw.Result> {
    return (this.#inprogress ??= this.#execute());
  }

  async #execute(): Promise<Raw.Result> {
    try {
      const { stream, getExitCode, raw } = await this.factory();

      const stdoutPass = new PassThrough();
      const stderrPass = new PassThrough();
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];

      stdoutPass.on("data", (chunk: Buffer) => {
        stdout.push(chunk);
        this.#enqueue({ kind: "out", data: chunk });
      });
      stderrPass.on("data", (chunk: Buffer) => {
        stderr.push(chunk);
        this.#enqueue({ kind: "err", data: chunk });
      });

      if (raw) stream.pipe(stdoutPass);
      else this.dockerode.modem.demuxStream(stream, stdoutPass, stderrPass);

      await new Promise<void>((resolve, reject) => {
        stream.on("end", resolve);
        stream.on("error", reject);
      });

      this.#enqueue(); // signal end of chunks

      return {
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        exit: await getExitCode(),
      };
    } catch (err) {
      this.#enqueue();
      return {
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
        exit: 1,
        error: err instanceof Error ? err : new Error(String(err)),
      };
    }
  }

  #enqueue(item?: Raw.Chunk) {
    this.#queue.push(item);
    this.#notify?.();
    this.#notify = undefined;
  }

  /**
   * Await the full result of the command. Never throws — errors are captured
   * in the returned object as `exception` alongside a non-zero `exitCode`.
   *
   * Can be called after `.chunks()` to retrieve the exit code (stdout/stderr
   * will reflect the full accumulated output regardless).
   */
  complete(): Promise<CompletedResult<string, string>>;
  complete(encoding: "buffer"): Promise<CompletedResult<Buffer, Buffer>>;
  complete(encoding: "string"): Promise<CompletedResult<string, string>>;
  complete<
    Out extends Encoding = "string",
    Err extends Encoding = "string",
  >(encoding: {
    out?: Out;
    err?: Err;
  }): Promise<CompletedResult<Encoded<Out>, Encoded<Err>>>;
  async complete(
    encoding?: Encoding | ResolvedEncoding,
  ): Promise<CompletedResult<unknown, unknown>> {
    const { stdout, stderr, exit, error } = await this.#open();
    const { out, err } = resolve(encoding);
    return { out: encode(stdout, out), err: encode(stderr, err), exit, error };
  }

  /**
   * Yield stdout/stderr chunks as they arrive. After iteration completes,
   * call `.complete()` to retrieve the exit code.
   */
  chunks(): AsyncGenerator<Chunk<string, string>>;
  chunks(encoding: "buffer"): AsyncGenerator<Chunk<Buffer, Buffer>>;
  chunks(encoding: "string"): AsyncGenerator<Chunk<string, string>>;
  chunks<
    Out extends Encoding = "string",
    Err extends Encoding = "string",
  >(encoding: {
    out?: Out;
    err?: Err;
  }): AsyncGenerator<Chunk<Encoded<Out>, Encoded<Err>>>;
  async *chunks(
    encoding?: Encoding | ResolvedEncoding,
  ): AsyncGenerator<Chunk<any, any>> {
    this.#open();
    const resolved = resolve(encoding);
    while (true) {
      if (this.#queue.length === 0)
        await new Promise<void>((resolve) => (this.#notify = resolve));
      const item = this.#queue.shift()!;
      if (!item) break;
      yield { ...item, data: encode(item.data, resolved[item.kind]) };
    }
  }
}
