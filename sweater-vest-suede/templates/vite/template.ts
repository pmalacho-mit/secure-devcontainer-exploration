import { mount } from "svelte";
import "./app.css";
import Closet from "<path>/sweater-vest-suede/Closet.svelte";

const app = mount(Closet, {
  target: document.getElementById("app")!,
  props: {
    glob: import.meta.glob("/<folder>/**/*.test.svelte"),
  },
});

export default app;
