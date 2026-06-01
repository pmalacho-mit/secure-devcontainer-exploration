import Dockerode, { type ImageBuildOptions } from "dockerode";
import { PassThrough } from "node:stream";
import CommandStream from "./CommandStream.js";
import { execFileAsync } from "./exec.js";

type FollowProgressEvent = {
  stream?: string;
  error?: string;
  [key: string]: unknown;
};

/** The underlying Dockerode instance (for advanced use cases). */
const dockerode = new Dockerode() as Dockerode & {
  /**
   * The `followProgress` method is not included in the Dockerode type definitions, so we augment the type here.
   * Added to library via: https://github.com/apocas/dockerode/pull/824
   * @param stream
   * @param onFinished
   * @param onProgress
   * @returns
   */
  followProgress: (
    stream: NodeJS.ReadableStream,
    onFinished: (err: Error | null, output: FollowProgressEvent[]) => void,
    onProgress?: (event: FollowProgressEvent) => void,
  ) => void;
};

export { dockerode };

const tryer =
  <Fn extends (...args: any[]) => Promise<any>>(fn: Fn) =>
  (...args: Parameters<Fn>): ReturnType<Fn> | Promise<undefined> =>
    fn(...args).catch(() => {});

/**
 * Escape hatch: run an arbitrary `docker` CLI command.
 * Prefer the structured `image` and `container`, APIs where
 * possible — this exists for one-off commands that dockerode doesn't wrap.
 *
 * **NOTE:** There is an existing bug: https://github.com/devcontainers/features/issues/483
 * which leads to exec commands to time out (by default) after ~500ms.
 *
 * @param args - Arguments passed directly to the docker CLI.
 *               Example: `docker(["rmi", "-f", "my-image"])`
 * @param cwd  - Working directory for the process. Default: process.cwd()
 *
 * Also exposes `.exec()` and `.verify()` as properties.
 */
export const docker = Object.assign(
  async (args: string[], cwd?: string) =>
    execFileAsync("docker", args, { cwd, maxBuffer: 16 * 1024 * 1024 }),
  {
    /**
     * Check whether the Docker daemon is reachable.
     * @returns `true` if the daemon responds, `false` otherwise.
     */
    verify: async (): Promise<boolean> => {
      try {
        await dockerode.ping();
        return true;
      } catch {
        return false;
      }
    },
    ...(() => {
      /**
       * Creates a Docker network.
       * @param Name - The name of the network.
       */
      const createNetwork = async (Name: string) =>
        dockerode.createNetwork({ Name });
      return {
        createNetwork,
        /**
         * Attempt to create a Docker network, silently ignores errors (e.g. already exists).
         * @param Name - The name of the network.
         */
        tryCreateNetwork: tryer(createNetwork),
      };
    })(),
    ...(() => {
      /**
       * Removes a Docker network.
       * @param Name - The name of the network.
       */
      const removeNetwork = async (Name: string) =>
        dockerode.getNetwork(Name).remove();
      return {
        removeNetwork,
        /**
         * Attempt to remove a Docker network, silently ignores errors (e.g. does not exist).
         * @param Name - The name of the network.
         */
        tryRemoveNetwork: tryer(removeNetwork),
      };
    })(),
  },
);

export const image = {
  /**
   * Return the full metadata for a local image.
   * @param name - Image name or id. Example: "node:20", "sha256:abc123"
   */
  inspect: async (name: string): Promise<Dockerode.ImageInspectInfo> =>
    dockerode.getImage(name).inspect(),

  /**
   * Build a Docker image from a build context directory.
   * @param tag - Tag to apply to the built image. Example: "my-app:latest"
   * @param context - Path to the directory containing the Dockerfile.
   * @param buildArgs - Build-time variables. Example: `{ BROWSER: "chromium" }`
   */
  build: (
    tag: string,
    context: string,
    options?: ImageBuildOptions & {
      /**
       * Restrict the context to specific files or directories.
       * If you experience much longer build times than expected,
       * try setting this to only the files needed for the build.
       */
      include?: string[];
    },
  ): CommandStream =>
    new CommandStream(dockerode, async () => {
      const { include, ...buildOptions } = options ?? {};
      const src = await dockerode.buildImage(
        { context, src: include ?? ["."] },
        { t: tag, ...buildOptions },
      );

      const out = new PassThrough();
      let resolveExit!: (code: number) => void;
      const exitCodePromise = new Promise<number>((res) => (resolveExit = res));

      dockerode.followProgress(
        src,
        (err) => {
          resolveExit(err ? 1 : 0);
          out.end();
        },
        (event) => {
          if (event.stream) out.push(event.stream);
          else if (event.error) out.push(`ERROR: ${event.error}\n`);
        },
      );

      return {
        stream: out,
        getExitCode: () => exitCodePromise,
        raw: true,
      };
    }),

  /**
   * Remove a local image.
   * @param name - Image name or id.
   * @param force - Force removal. Default: true
   */
  remove: async (name: string, force = true): Promise<void> => {
    await dockerode.getImage(name).remove({ force });
  },
};

// ---------------------------------------------------------------------------
// container
// ---------------------------------------------------------------------------

export namespace Container {
  type Env = Record<string, string>;

  export type PublishedPort = {
    /** The port or interface:port on the host machine. Example: "8080" or "127.0.0.1:8080" */
    host: string | number;
    /** The port exposed by the container. Example: "3000" */
    container: string | number;
  };

  export type MountedVolume = {
    /** The host path to mount. Example: "/host/data" */
    source: string;
    /** The container path to mount to. Example: "/app/data" */
    target: string;
    /** Whether the volume should be read-only. Default: false (writable) */
    readOnly?: boolean;
  };

  export type RunOptions = {
    /** Docker image to run (required). */
    image: string;
    /** Command and arguments to execute in the container. */
    command?: string[];
    /** Container name for identification. */
    name?: string;
    /** Network to connect the container to. */
    network?: string;
    /** Environment variables to set in the container. */
    env?: Env;
    /** Ports to publish from container to host. */
    ports?: PublishedPort[];
    /** Volumes to mount into the container. */
    volumes?: MountedVolume[];
    /** Additional create options merged into the Dockerode config. */
    extraCreateOptions?: Partial<Dockerode.ContainerCreateOptions>;
    /** Automatically remove container when it stops. Default: true */
    removeOnStop?: boolean;
  };

  export type Instance = string | Dockerode.Container;
}

const resolve = (container: Container.Instance) =>
  typeof container === "string" ? dockerode.getContainer(container) : container;

export const container = {
  resolve,

  /**
   * Inspect a container, returning full metadata.
   * @param container - The container name or id or Dockerode.Container instance.
   */
  inspect: async (container: Container.Instance) =>
    resolve(container).inspect(),

  /**
   * Check whether a container is currently running.
   * @param container - The container name or id or Dockerode.Container instance.
   */
  isRunning: async (container: Container.Instance) => {
    try {
      const info = await resolve(container).inspect();
      return info.State.Running;
    } catch {
      return false;
    }
  },

  /**
   * Start an existing container.
   * @param container - The container name or id or Dockerode.Container instance.
   */
  start: async (container: Container.Instance) => resolve(container).start(),

  /**
   * Run a command inside a running container.
   * Returns a `CommandStream` synchronously — call `.complete()` to await
   * the buffered result or `.chunks()` to stream output.
   *
   * @param container - The container name or id or Dockerode.Container instance.
   * @param args - Command and arguments to execute inside the container.
   */
  exec: (container: Container.Instance, args: string[]) =>
    new CommandStream(dockerode, async () => {
      const exec = await resolve(container).exec({
        Cmd: args,
        AttachStdout: true,
        AttachStderr: true,
      });
      return {
        stream: await exec.start({ Detach: false, Tty: false }),
        getExitCode: async () => (await exec.inspect()).ExitCode ?? 0,
      };
    }),

  /**
   * Create and start a new container from an image.
   * @param options - Configuration for the container.
   * @returns The created Dockerode.Container handle.
   */
  run: async ({
    image: imageName,
    command,
    name,
    network,
    env,
    ports,
    volumes,
    extraCreateOptions,
    removeOnStop = true,
  }: Container.RunOptions) => {
    const portBindings: Dockerode.PortMap = {};
    const exposedPorts: Record<string, Record<string, never>> = {};

    if (ports)
      for (const { host, container: containerPort } of ports) {
        const key = `${containerPort}/tcp`;
        const hostStr = String(host);
        const colonIdx = hostStr.lastIndexOf(":");
        const hostIp = colonIdx > 0 ? hostStr.slice(0, colonIdx) : "";
        const hostPort = colonIdx > 0 ? hostStr.slice(colonIdx + 1) : hostStr;

        exposedPorts[key] = {};
        portBindings[key] = [{ HostIp: hostIp, HostPort: hostPort }];
      }

    const binds: string[] = [];
    if (volumes)
      for (const { source, target, readOnly } of volumes)
        binds.push(`${source}:${target}${readOnly ? ":ro" : ""}`);

    const container = await dockerode.createContainer({
      Image: imageName,
      ...(command?.length && { Cmd: command }),
      ...(name && { name }),
      ...(env && { Env: Object.entries(env).map(([k, v]) => `${k}=${v}`) }),
      ExposedPorts: exposedPorts,
      HostConfig: {
        PortBindings: portBindings,
        ...(binds.length && { Binds: binds }),
        ...(network && { NetworkMode: network }),
        AutoRemove: removeOnStop,
      },
      ...extraCreateOptions,
    });

    await container.start();
    return container;
  },

  /**
   * Stream the stdout/stderr of a container as a `CommandStream`.
   *
   * Attach before the container exits to avoid missing output. With
   * `removeOnStop: true` the container self-cleans after the stream closes,
   * so `container.remove()` is only needed when `removeOnStop` was set to
   * false.
   *
   * @param container - The container to stream logs from.
   */
  log: (container: Container.Instance): CommandStream =>
    new CommandStream(dockerode, async () => ({
      stream: await resolve(container).logs({
        stdout: true,
        stderr: true,
        follow: true,
      }),
      getExitCode: async () => (await resolve(container).wait()).StatusCode,
    })),

  ...(() => {
    /**
     * Remove a container.
     * @param container - The container name or id or Dockerode.Container instance.
     * @param force - Force removal without stopping. Default: true
     */
    const remove = async (container: Container.Instance, force = true) =>
      resolve(container).remove({ force });

    return {
      remove,
      /**
       * Attempt to remove a container.
       * @param container - The container name or id or Dockerode.Container instance.
       * @param force - Force removal without stopping. Default: true
       */
      tryRemove: tryer(remove),
    };
  })(),
};
