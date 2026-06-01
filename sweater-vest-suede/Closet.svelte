<script lang="ts" module>
  export type Props = {
    /**
     * The result of invoking `import.meta.glob` using a search pattern to surface all of your tests.
     *
     * NOTE: The location of your vite config corresponds to `/`.
     */
    glob: Record<string, unknown>;
  };

  interface Tree {
    [key: string]: Tree | string;
  }

  const sortedEntries = (node: Tree): Array<[string, Tree | string]> =>
    Object.entries(node).sort(([aKey, aValue], [bKey, bValue]) => {
      const aIsDir = typeof aValue !== "string";
      const bIsDir = typeof bValue !== "string";
      if (aIsDir !== bIsDir) return aIsDir ? -1 : 1;
      return aKey.localeCompare(bKey);
    });

  const isModule = (
    value: unknown,
  ): value is () => Promise<{ default: Component }> =>
    typeof value === "function";

  const candidates = <T extends string>(value: T) => {
    const trimmed = value.trim();
    const normalized = trimmed.replace(/^\/+/, "");
    const base = normalized.replace(/\.svelte$/, "").replace(/\.test$/, "");

    return [
      normalized,
      base,
      `${base}.svelte`,
      `${base}.test.svelte`,
      `/${normalized}`,
      `/${base}`,
      `/${base}.svelte`,
      `/${base}.test.svelte`,
    ] as const;
  };

  const resolve = (
    value: string,
    entries: Props["glob"],
  ): string | undefined => {
    const paths = Object.keys(entries);

    for (const candidate of candidates(value))
      if (candidate in entries) return candidate;

    const selectedBaseName = value
      .trim()
      .replace(/^\/+/, "")
      .split("/")
      .pop()
      ?.replace(/\.svelte$/, "")
      .replace(/\.test$/, "");

    if (!selectedBaseName) return;

    const fuzzyMatches = paths.filter((path) => {
      const fileName = path.split("/").pop();
      if (!fileName) return false;

      const baseName = fileName
        .replace(/\.test\.svelte$/, "")
        .replace(/\.svelte$/, "");

      return baseName === selectedBaseName;
    });

    return fuzzyMatches[0];
  };
</script>

<script lang="ts">
  import { onMount, type Component } from "svelte";
  import { tryPost, param, server } from "./report/client.js";
  import { SvelteURLSearchParams } from "svelte/reactivity";

  const params = new SvelteURLSearchParams();

  let { glob }: Props = $props();

  onMount(() => {
    const url = new URL(window.location.href);
    const component = param("component", url);
    if (component) return params.set("component", component);
    const reportServer = server(url);
    if (reportServer)
      tryPost({ type: "closet-ready", paths: Object.keys(glob) }, reportServer);
  });

  const selected = $derived(params.get("component"));

  const tests = $derived.by<Tree>(() => {
    const tree: Tree = {};

    for (const path of Object.keys(glob)) {
      const segments = path.replace(/^\/+/, "").split("/").filter(Boolean);
      const fileName = segments.pop();

      if (!fileName) continue;

      const leafName = fileName
        .replace(/\.test\.svelte$/, "")
        .replace(/\.svelte$/, "");

      let cursor = tree;
      for (const segment of segments) {
        const existing = cursor[segment];
        if (typeof existing === "string" || !existing) cursor[segment] = {};
        cursor = cursor[segment] as Tree;
      }

      cursor[leafName] = path;
    }

    return tree;
  });

  const select = (component: string) => {
    params.set("component", component);
    const url = new URL(window.location.href);
    url.searchParams.set("component", component);
    window.history.pushState({}, "", url);
  };

  const component = $derived.by(() => {
    if (!selected) return;

    const selectedPath = resolve(selected, glob);

    if (!selectedPath)
      return console.error(
        `Could not resolve component from selection "${selected}".`,
      );

    return isModule(glob[selectedPath])
      ? glob[selectedPath]().then(({ default: Component }) => Component)
      : console.error(
          `Expected glob result for "${selectedPath}" to be an importer function, but got:`,
          glob[selectedPath],
        );
  });
</script>

<h1>Tests</h1>

{#if component}
  {#await component then Component}
    <Component />
  {/await}
{:else}
  {#snippet renderTree(node: Tree)}
    <ul>
      {#each sortedEntries(node) as [name, value]}
        <li>
          {#if typeof value === "string"}
            <button type="button" onclick={() => select(value)}>
              {name}
            </button>
          {:else}
            <details open>
              <summary>{name}</summary>
              {@render renderTree(value)}
            </details>
          {/if}
        </li>
      {/each}
    </ul>
  {/snippet}

  {@render renderTree(tests)}
{/if}
