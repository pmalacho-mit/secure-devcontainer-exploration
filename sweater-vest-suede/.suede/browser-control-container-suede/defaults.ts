import type { Browser } from ".";

const defaults = {
  container: (browser: Browser) => `browser-control-${browser}`,
  image: (browser: Browser) => `${defaults.container(browser)}:latest`,
  command: ["bash", "-c", "tail -f /dev/null"],
};

export default defaults;
