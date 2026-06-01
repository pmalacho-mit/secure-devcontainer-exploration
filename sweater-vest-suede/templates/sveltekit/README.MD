1. Create a `tests/` directory somewhere in your `src/routes/` directory.
2. Copy [+page.svelte](./+page.svelte) to the `tests/` directory.
3. When building your project, prefix your build command with an invocation of [with-exclude-tests-routes-from-build.sh](./with-exclude-tests-routes-from-build.sh) to exclude the `tests/` directory from the build. For example, if your build command is `svelte-kit build`, you would run `./<path>/with-exclude-tests-routes-from-build.sh svelte-kit build`.
   > How this script works is simply: (1) rename the `+page.svelte` file in the `tests/` directory to `_page.svelte`, (2) run the build command, and then (3) rename the file back to `+page.svelte`.
