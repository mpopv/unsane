import { describe, expect, it } from "vitest";
import { sanitize } from "./htmlSanitizer.js";

describe("slice-based tokenizer", () => {
  it("returns safe plain text without entering the markup parser", () => {
    expect(sanitize("plain text with unicode ✓")).toBe(
      "plain text with unicode ✓",
    );
  });

  it("removes C1 controls when plain text leaves the fast path", () => {
    expect(sanitize("before\u0080after")).toBe("beforeafter");
  });

  it("normalizes mixed-case tokens around source-range boundaries", () => {
    expect(
      sanitize('<DIV CLASS="safe" data-drop=value>text</DIV>', {
        allowedTags: ["div"],
        allowedAttributes: { div: ["class"] },
      }),
    ).toBe('<div class="safe">text</div>');
  });
});
