import type { Report } from ".";

const ms = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(2)}s` : `${n}ms`);

const compLabel = (path: string): string =>
  path
    .replace(/^\/+/, "")
    .replace(/^(src|lib|packages\/[^/]+\/src)\//, "")
    .replace(/\.test\.svelte$/, "")
    .replace(/\.svelte$/, "");

const ctrLabel = (c: Report.Result.Container): string =>
  c.category ?? `container ${c.index + 1}`;

const tstLabel = (t: Report.Result.Test): string =>
  t.name ?? t.components ?? `test ${t.index + 1}`;

const heading = (level: number, text: string) => `${"#".repeat(level)} ${text}`;

const code = {
  inline: (s: string) => `\`${s}\``,
  block: (s: string, lang = "") => `\`\`\`${lang}\n${s}\n\`\`\``,
};

const htmlSummary = (content: string) => `<summary>${content}</summary>`;

const details = (title: string, content: string, inline = false) =>
  `<details>${htmlSummary(title)}${inline ? "" : "\n\n"}${content}${inline ? "" : "\n\n"}</details>`;

/** True when the container level should be omitted: single container with no explicit name. */
const omitContainerLevel = (containers: Report.Result.Container[]): boolean =>
  containers.length === 1 && containers[0].category == null;

export const render = {
  trace: (artifacts: Report.Result.Run["artifacts"]) =>
    artifacts.map((a) =>
      typeof a === "string"
        ? `- ${a}`
        : `- ![capture (${a.type})](${a.dataUri})`,
    ),

  /** Browser is always shown — it's per-run so it's always meaningful. */
  failedRun: (
    component: Report.Result.Component,
    container: Report.Result.Container,
    test: Report.Result.Test,
    run: Report.Result.Run,
  ): string => {
    const path = `${ctrLabel(container)} › ${tstLabel(test)}`;
    const lines = [
      heading(
        3,
        `${code.inline(compLabel(component.component))} › ${path} *(${run.browser})*`,
      ),
      "",
    ];

    const trace = render.trace(run.artifacts);
    lines.push(...trace);

    if (run.error) {
      const { message, stack } = run.error;
      lines.push(
        `${trace.length + 1}. ❌ **${message.split("\n")[0] ?? message}**`,
      );
      if (stack) {
        lines.push("");
        lines.push(details("Stack trace", code.block(stack)));
      }
    }

    return lines.join("\n");
  },

  /**
   * Single browser → browser name on the component header line.
   * Multiple browsers → browser tag(s) inline on each test line.
   * Container level is omitted when there is exactly one unnamed container.
   */
  passedComponent: (
    component: Report.Result.Component,
    multipleBrowsers: boolean,
  ): string => {
    const allRuns = component.containers.flatMap(({ tests }) =>
      tests.flatMap(({ runs }) => runs),
    );
    const passedRuns = allRuns.filter(({ status }) => status === "passed");
    if (passedRuns.length === 0) return "";

    const totalMs = allRuns.reduce((s, r) => s + r.durationMs, 0);
    const headerBrowser = !multipleBrowsers
      ? ` · ${[...new Set(allRuns.map((r) => r.browser))].join(", ")}`
      : "";

    const lines: string[] = [
      `**${code.inline(compLabel(component.component))}**${headerBrowser} · ${passedRuns.length} of ${allRuns.length} passed · ${ms(totalMs)}`,
      "",
    ];

    const omitCtr = omitContainerLevel(component.containers);

    for (const container of component.containers) {
      if (!omitCtr) lines.push(`- ${ctrLabel(container)}`);
      const ti = omitCtr ? "" : "  "; // test indent
      const ai = ti + "  "; // artifact indent

      for (const test of container.tests) {
        const passed = test.runs.filter(({ status }) => status === "passed");
        if (passed.length === 0) continue;

        const name = tstLabel(test);
        const hasArtifacts = passed.some((r) => r.artifacts.length > 0);

        if (!hasArtifacts) {
          // Collapse all passing runs onto one line; browser tags when multi-browser.
          const bTags = multipleBrowsers
            ? " " + passed.map((r) => `*(${r.browser})*`).join(" ")
            : "";
          lines.push(`${ti}- ${name}${bTags}`);
        } else {
          // Separate line per run so artifacts attach to the right run.
          for (const run of passed) {
            const bTag = multipleBrowsers ? ` *(${run.browser})*` : "";
            lines.push(`${ti}- ${name}${bTag}`);
            const { artifacts } = run;
            if (artifacts.length === 0) continue;
            lines.push(
              ...[
                "",
                `${ai}<details><summary>${artifacts.length} ${artifacts.length === 1 ? "event" : "events"}</summary>`,
                "",
                ...render.trace(artifacts).map((t) => `${ai}${t}`),
                "",
                `${ai}</details>`,
                "",
              ],
            );
          }
        }
      }
    }

    return lines.join("\n");
  },

  /** Browser is always shown inline. Container level omitted when single and unnamed. */
  skipped: (results: Report.Result.Component[]): string[] => {
    const lines: string[] = [];
    for (const component of results) {
      const omitCtr = omitContainerLevel(component.containers);
      for (const container of component.containers) {
        const tests = container.tests.filter((t) =>
          t.runs.some(({ status }) => status === "skipped"),
        );
        if (tests.length === 0) continue;

        if (!omitCtr)
          lines.push(
            `- ${code.inline(compLabel(component.component))} › ${ctrLabel(container)}`,
          );

        const ti = omitCtr ? "" : "  ";
        for (const test of tests) {
          for (const run of test.runs.filter(
            ({ status }) => status === "skipped",
          )) {
            const prefix = omitCtr
              ? `${code.inline(compLabel(component.component))} › `
              : "";
            lines.push(`${ti}- ${prefix}${tstLabel(test)} *(${run.browser})*`);
          }
        }
      }
    }
    return lines;
  },
};

/**
 * Renders a Markdown report string from accumulated test results.
 *
 * Layout:
 *   1. Summary line — failure count (loud), totals, duration.
 *   2. ❌ Failures — each failing run as a heading with trace + error.
 *      Stack trace is collapsible. Browser always shown.
 *   3. ✅ Passed — grouped by component → container → test.
 *      Container level omitted when single and unnamed.
 *      Browser on component header (single) or per-test (multi).
 *   4. ⏭ Skipped — same nesting; browser always shown inline.
 *
 * No side effects — pure function suitable for unit testing.
 */
export const renderMarkdown = (input: Report.RenderInput): string => {
  const allRuns = input.results.flatMap(({ containers }) =>
    containers.flatMap(({ tests }) => tests.flatMap(({ runs }) => runs)),
  );

  const failedRuns: Array<{
    component: Report.Result.Component;
    container: Report.Result.Container;
    test: Report.Result.Test;
    run: Report.Result.Run;
  }> = [];

  for (const component of input.results)
    for (const container of component.containers)
      for (const test of container.tests)
        for (const run of test.runs)
          if (run.status === "failed")
            failedRuns.push({ component, container, test, run });

  const totalPassed = allRuns.filter(
    ({ status }) => status === "passed",
  ).length;
  const totalSkipped = allRuns.filter(
    ({ status }) => status === "skipped",
  ).length;
  const totalMs = allRuns.reduce((s, r) => s + r.durationMs, 0);

  const multipleBrowsers =
    new Set(allRuns.map(({ browser }) => browser)).size > 1;

  const statusLine =
    allRuns.length === 0
      ? "*No tests were run.*"
      : [
          failedRuns.length > 0
            ? `🔴 **${failedRuns.length} failed**`
            : "🟢 **all passed**",
          totalPassed > 0 ? `${totalPassed} passed` : "",
          totalSkipped > 0 ? `${totalSkipped} skipped` : "",
          `${allRuns.length} total`,
          ms(totalMs),
        ]
          .filter(Boolean)
          .join(" · ");

  const lines: string[] = [
    "# Sweater Vest Report",
    "",
    statusLine,
    `Generated ${input.generatedAt} · [${input.closet}](${input.closet})`,
    "",
    "---",
    "",
  ];

  if (allRuns.length === 0) return lines.join("\n");

  if (failedRuns.length > 0) {
    lines.push(`## ❌ Failures (${failedRuns.length})`, "");
    for (const { component, container, test, run } of failedRuns) {
      lines.push(render.failedRun(component, container, test, run));
      lines.push("");
    }
    lines.push("---", "");
  }

  if (totalPassed > 0) {
    lines.push(`## ✅ Passed (${totalPassed})`, "");
    for (const component of input.results) {
      const rendered = render.passedComponent(component, multipleBrowsers);
      if (rendered) lines.push(rendered);
    }
    if (totalSkipped > 0) lines.push("---", "");
  }

  if (totalSkipped > 0) {
    lines.push(`## ⏭ Skipped (${totalSkipped})`, "");
    lines.push(...render.skipped(input.results));
    lines.push("");
  }

  return lines.join("\n");
};
