<script lang="ts">
  import { Sweater } from "_sweater-vest-suede";
  import Component, { Model } from "_.svelte";

  class Pocket {
    model = $state<Model>()!;
    constructor(model: Model) {
      this.model = model;
    }
  }
</script>

<Sweater
  body={async ({ set }) => {
    const pocket = set(new Pocket(new Model()));
  }}
>
  {#snippet vest({ model }: Pocket)}
    <Component {model} />
  {/snippet}
</Sweater>
