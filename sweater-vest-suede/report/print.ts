import type { Report } from ".";

const ms = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(2)}s` : `${n}ms`);

const compLabel = (path: string): string =>
  path
    .replace(/^\/+/, "")
    .replace(/^(src|lib|packages\/[^/]+\/src)\//, "")
    .replace(/\.test\.svelte$/, "")
    .replace(/\.svelte$/, "");

const firstErrorLine = (
  error: NonNullable<Report.Result.Run["error"]>,
): string => {
  const line = error.message.split("\n")[0] ?? "";
  return line.length > 120 ? line.slice(0, 120) + "…" : line;
};

/**
 * Writes a Vitest-style summary to `write` (defaults to process.stdout).
 * Accepts a `write` override so the function can be tested without monkey-patching stdout.
 * Hierarchy: component → container → test → browser run.
 */
export const printReport = (
  input: Report.RenderInput,
  options?: { output?: string; write?: (s: string) => void },
): void => {
  const write = options?.write ?? process.stdout.write.bind(process.stdout);
  const tty = !options?.write && process.stdout.isTTY;

  const green = (s: string) => (tty ? `\x1b[32m${s}\x1b[0m` : s);
  const red = (s: string) => (tty ? `\x1b[31m${s}\x1b[0m` : s);
  const yellow = (s: string) => (tty ? `\x1b[33m${s}\x1b[0m` : s);
  const dim = (s: string) => (tty ? `\x1b[2m${s}\x1b[0m` : s);
  const bold = (s: string) => (tty ? `\x1b[1m${s}\x1b[0m` : s);

  const divider = dim("─".repeat(45));

  write(`\n${bold("sweater-vest report")}\n`);
  write(`${divider}\n`);

  const allRunsFlat = input.results.flatMap(({ containers }) =>
    containers.flatMap(({ tests }) => tests.flatMap(({ runs }) => runs)),
  );
  const allBrowsers = [...new Set(allRunsFlat.map(({ browser }) => browser))];
  const multipleBrowsers = allBrowsers.length > 1;
  // Single-browser: append to each component line. Multi-browser: shown per failure item.
  const componentBrowserSuffix = !multipleBrowsers
    ? dim(` — ${allBrowsers[0]}`)
    : "";

  for (const component of input.results) {
    const label = compLabel(component.component);
    const allRuns = component.containers.flatMap(({ tests }) =>
      tests.flatMap(({ runs }) => runs),
    );

    const passed = allRuns.filter(({ status }) => status === "passed").length;
    const failed = allRuns.filter(({ status }) => status === "failed").length;
    const skipped = allRuns.filter(({ status }) => status === "skipped").length;
    const total = allRuns.length;
    const totalMs = allRuns.reduce((s, r) => s + r.durationMs, 0);

    const breakdown = [
      passed > 0 ? `${passed} passed` : "",
      failed > 0 ? `${failed} failed` : "",
      skipped > 0 ? `${skipped} skipped` : "",
      `${total} total`,
    ]
      .filter(Boolean)
      .join(", ");

    if (failed > 0) {
      write(
        ` ${red("FAIL")}  ${label}   ${dim(`(${breakdown}, ${ms(totalMs)})`)}${componentBrowserSuffix}\n`,
      );
      for (const container of component.containers) {
        const ctrLbl = container.category ?? `container ${container.index + 1}`;
        for (const test of container.tests) {
          for (const run of test.runs.filter(
            ({ status }) => status === "failed",
          )) {
            const testName = test.name ?? test.components ?? "(unnamed)";
            const browserPart = multipleBrowsers ? ` *(${run.browser})*` : "";
            const location = dim(`[${ctrLbl} / test ${test.index + 1}]`);
            write(`       ${red("●")} ${testName}${browserPart} ${location}\n`);
            if (run.error)
              write(`         ${dim(firstErrorLine(run.error))}\n`);
          }
        }
      }
    } else if (skipped === total) {
      write(
        ` ${yellow("SKIP")}  ${label}   ${dim(`(${total} tests skipped)`)}${componentBrowserSuffix}\n`,
      );
    } else {
      write(
        ` ${green("PASS")}  ${label}   ${dim(`(${breakdown}, ${ms(totalMs)})`)}${componentBrowserSuffix}\n`,
      );
    }
  }

  write(`${divider}\n`);

  const totalPassed = allRunsFlat.filter(
    ({ status }) => status === "passed",
  ).length;
  const totalFailed = allRunsFlat.filter(
    ({ status }) => status === "failed",
  ).length;
  const totalSkipped = allRunsFlat.filter(
    ({ status }) => status === "skipped",
  ).length;
  const grandTotalMs = allRunsFlat.reduce((s, r) => s + r.durationMs, 0);

  const countParts = [
    totalPassed > 0 ? green(`${totalPassed} passed`) : "",
    totalFailed > 0 ? red(`${totalFailed} failed`) : "",
    totalSkipped > 0 ? yellow(`${totalSkipped} skipped`) : "",
    dim(`${allRunsFlat.length} total`),
  ].filter(Boolean);

  write(`Tests:  ${countParts.join(", ")}\n`);
  write(`Time:   ${ms(grandTotalMs)}\n`);
  if (options?.output) write(`Report: ${options.output}\n`);
  write("\n");
};
