import { describe, expect, it } from "vitest";
import { createSanitizer, sanitize } from "./htmlSanitizer.js";

describe("createSanitizer", () => {
  it("reuses the default policy", () => {
    const compiled = createSanitizer();
    const input = '<div onclick="alert(1)"><strong>safe</strong></div>';

    expect(compiled(input)).toBe(sanitize(input));
  });

  it("normalizes and snapshots a custom policy", () => {
    const options = {
      allowedTags: ["DIV"],
      allowedAttributes: { DIV: ["CLASS"] },
    };
    const compiled = createSanitizer(options);

    options.allowedTags.length = 0;
    options.allowedAttributes.DIV.length = 0;

    expect(compiled('<DIV CLASS="safe" id="drop">ok</DIV>')).toBe(
      '<div class="safe">ok</div>',
    );
  });

  it("enforces the compiled input limit on every call", () => {
    const compiled = createSanitizer({ maxInputLength: 4 });

    expect(() => compiled("12345")).toThrow(
      "Input length 5 exceeds maxInputLength 4.",
    );
    expect(compiled("1234")).toBe("1234");
  });
});
