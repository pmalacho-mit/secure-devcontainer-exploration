<script lang="ts">
  import { Sweater } from "_sweater-vest-suede";
  import Component from "_.svelte";

  class Pocket {}
</script>

<Sweater
  body={async ({ set }) => {
    const pocket = set(new Pocket());
  }}
>
  {#snippet vest(pocket: Pocket)}  
    <Component />
  {/snippet}
</Sweater>
