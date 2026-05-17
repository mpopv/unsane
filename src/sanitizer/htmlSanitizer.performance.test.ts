import { describe, expect, it } from "vitest";
import { performance } from "node:perf_hooks";
import { sanitize } from "./htmlSanitizer.js";

function expectSanitizeUnder(
  name: string,
  html: string,
  maxDurationMs: number,
): string {
  const start = performance.now();
  const output = sanitize(html, { maxInputLength: Infinity });
  const durationMs = performance.now() - start;

  expect(
    durationMs,
    `${name} took ${durationMs.toFixed(2)}ms; budget is ${maxDurationMs}ms`,
  ).toBeLessThan(maxDurationMs);

  return output;
}

describe("htmlSanitizer performance guardrails", () => {
  it("sanitizes large repetitive fragments within budget", () => {
    const html = Array.from(
      { length: 2_000 },
      (_, index) =>
        `<p class="row-${index}"><a href="/docs/${index}" target="_blank">Docs ${index}</a></p>`,
    ).join("");

    const output = expectSanitizeUnder("large repetitive fragments", html, 750);

    expect(output).toContain('rel="noopener noreferrer"');
    expect(output).toContain("Docs 1999");
  });

  it("sanitizes deeply nested allowed tags within budget", () => {
    const depth = 1_000;
    const html = `${"<div>".repeat(depth)}content${"</div>".repeat(depth)}`;
    const output = expectSanitizeUnder("deep nesting", html, 500);

    expect(output.startsWith("<div><div>")).toBe(true);
    expect(output).toContain("content");
    expect(output.endsWith("</div></div>")).toBe(true);
  });

  it("sanitizes large attribute payloads within budget", () => {
    const payload = "safe-title ".repeat(20_000);
    const html = `<div title="${payload}" class="note">content</div>`;
    const output = expectSanitizeUnder("large attribute payload", html, 500);

    expect(output).toContain('class="note"');
    expect(output).toContain("content");
  });
});
