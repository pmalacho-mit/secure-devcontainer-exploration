<script lang="ts" module>
  import type { Props as RunnerProps, Pocket } from "./Runner.svelte";
  import type { Props as ContainerProps } from "./Container.svelte";
  import Container, { mechanism, next, setTotal } from "./Container.svelte";
  import type { Snippet } from "svelte";
  import { createContainerMap } from "./utils/container-map.js";
  import { suiteReady } from "./report/client.js";

  type ConfigProps = ContainerProps & {
    target?: HTMLElement;
    config: true;
    children?: Snippet;
    category?: string;
  };

  type Props<T extends Pocket> =
    Pocket extends Required<T>
      ? keyof T extends never
        ? RunnerProps<{}>
        : ConfigProps
      : RunnerProps<T>;

  const is = <T extends "config" | "test">(
    type: T,
    props: ConfigProps | RunnerProps<any>,
  ): props is T extends "config" ? ConfigProps : RunnerProps<any> => {
    const hasConfig = "config" in props && props.config;
    return type === "config" ? hasConfig : !hasConfig;
  };

  const containers = createContainerMap();

  const counts = {
    tests: 0,
    configs: 0,
    total: () => counts.tests + counts.configs,
    key: <T extends Pocket>(props: Props<T>) =>
      is("test", props) ? "tests" : "configs",
    add: <T extends Pocket>(props: Props<T>) => counts[counts.key(props)]++,
    subtract: <T extends Pocket>(props: Props<T>) =>
      counts[counts.key(props)]--,
  };

  /* TODO: Determine if this is only true when test is modified and live-reload triggers */
  const testHasChanged = <T extends Pocket>(props: Props<T>, index: number) =>
    is("test", props) && index < 0;

  const location = () => new URL(window.location.href);
  const testHasChangedParam = "reload-after-test-change";

  const tryReload = () => {
    const url = location();
    if (url.searchParams.has(testHasChangedParam))
      return console.error(
        "Reload parameter already set. Not reloading to avoid infinite loop.",
      );
    url.searchParams.set(testHasChangedParam, "1");
    window.location.href = url.toString(); // trigger reload
  };

  const tryRemoveReloadParam = () => {
    const url = location();
    if (!url.searchParams.has(testHasChangedParam)) return;
    url.searchParams.delete(testHasChangedParam);
    window.history.replaceState({}, "", url.toString());
  };

  const testCount = () => {
    let total = 0;
    containers.each((container) => (total += container.count()));
    return total;
  };
</script>

<script lang="ts" generics="T extends Pocket">
  import { onMount, tick } from "svelte";

  let props: Props<T> = $props();

  const index = counts.total();
  counts.add(props);

  let selfContained = $state(is("test", props) && index === 0);

  const getSelfContainer = async () => {
    selfContained = true;
    await tick();
    return containers.find(index)!;
  };

  const container = async () =>
    containers.context ?? containers.find(index) ?? (await getSelfContainer());

  onMount(async () => {
    if (testHasChanged(props, index)) tryReload();
    else tryRemoveReloadParam();

    if (is("test", props)) (await container()).push(props);
    counts.subtract(props);
    const allMounted = counts.total() === 0;
    if (!allMounted) return;
    setTotal(containers.total);
    suiteReady(testCount());
    containers.reset();
    next();
  });
</script>

{#if is("config", props)}
  {#if props.children}
    <Container
      bind:this={containers.current}
      {...props}
      mechanism={mechanism.nested}
    />
    {@render props.children()}
  {:else}
    <Container
      bind:this={containers[index]}
      {...props}
      mechanism={mechanism.sequential}
    />
  {/if}
{:else if selfContained}
  <Container
    bind:this={containers[index]}
    mechanism={mechanism.selfContained}
  />
{/if}

<style>
  :global(body > *:first-child) {
    display: block !important;
    width: 100vw;
    height: 100vh;
  }

  :global(.dv-sash) {
    background-color: black !important;
    width: 1px !important;
  }
</style>
