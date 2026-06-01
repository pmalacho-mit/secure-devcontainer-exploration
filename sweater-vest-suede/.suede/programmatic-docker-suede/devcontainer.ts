import { networkInterfaces } from "node:os";
import { container, type Container } from ".";
import { runCmd } from "./exec.js";

export const devcontainer = Object.assign(
  /**
   * Detect and return the current devcontainer by reading the hostname and resolving it to a container.
   * @returns The resolved devcontainer.
   */
  async () => {
    const { stdout } = await runCmd("hostname", []);
    const id = stdout.trim();

    if (/^[0-9a-f]{12,64}$/i.test(id))
      try {
        return container.resolve(id);
      } catch (e) {
        throw new Error(`Error resolving devcontainer id ${id}: ${String(e)}`);
      }

    throw new Error(
      "Could not detect devcontainer id from hostname; cannot use --network container:<id>",
    );
  },
  {
    /**
     * Detect and return the id of the current devcontainer by reading the hostname.
     * @throws If the hostname is not a valid container id or docker inspect fails.
     */
    id: () => devcontainer().then(({ id }) => id),
    /**
     * Return the NAME of the network the devcontainer is attached to, so sibling
     * containers can join it as ordinary peers (`--network <name>`) and reach
     * servers running inside the devcontainer via {@link devcontainer.ip}.
     *
     * This previously returned `container:<id>` (a shared network namespace), but
     * the security gate in front of the Docker socket rejects all cross-container
     * namespaces. Joining the dev network as a peer gives the same reachability
     * with strictly less privilege — the sibling can't bind the devcontainer's
     * own interfaces/loopback or impersonate its localhost services — which is
     * what the gate's "same access, or less" policy permits.
     * @param id - Explicit container id/instance. Defaults to the auto-detected devcontainer.
     * @throws If the devcontainer's network can't be determined.
     */
    network: async (id?: string) => {
      const { NetworkSettings } = await devcontainer.inspect(id);
      const names = Object.keys(NetworkSettings?.Networks ?? {});
      // The devcontainer is attached to its project's "dev" network, never the
      // gate network; prefer a non-gate network name defensively.
      const name = names.find((n) => !/(^|[-_])gate$/.test(n)) ?? names[0];
      if (!name)
        throw new Error("Could not determine the devcontainer's network");
      return name;
    },

    inspect: async (instance?: Container.Instance) =>
      container.inspect(instance ?? (await devcontainer())),

    /**
     * Return the devcontainer's non-loopback IPv4 address.
     *
     * Use this as the bind/connect address when a sibling container joined to
     * the devcontainer's network (see {@link devcontainer.network}) needs to
     * reach a server running inside the devcontainer. That container reaches the
     * devcontainer over the shared network via this eth0 address, not loopback,
     * so a `127.0.0.1`-bound server won't see it — bind servers to `0.0.0.0`.
     * @throws If no non-loopback IPv4 interface is found.
     */
    ip: (): string => {
      const ip = Object.values(networkInterfaces())
        .flat()
        .find((i) => i && !i.internal && i.family === "IPv4")?.address;
      if (ip) return ip;
      throw new Error("Could not determine devcontainer IP address");
    },
  },
);

export default devcontainer;
