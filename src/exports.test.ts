import { describe, it, expect } from "vitest";
import { sanitize, escape, encode, decode } from "./index.js";
import type { SanitizerOptions, Sanitizer } from "./index.js";

describe("Library exports", () => {
  it("should export all required functions", () => {
    expect(typeof sanitize).toBe("function");
    expect(typeof escape).toBe("function");
    expect(typeof encode).toBe("function");
    expect(typeof decode).toBe("function");
  });

  it("should have correct function signatures", () => {
    const input = "<div>test</div>";

    // Test sanitize function
    expect(sanitize(input)).toBeTruthy();
    expect(sanitize(input, {})).toBeTruthy();
    expect(sanitize(input, { allowedTags: ["div"] })).toBeTruthy();

    // Test escape function
    expect(escape(input)).toBeTruthy();

    // Test encode function
    expect(encode(input)).toBeTruthy();

    // Test decode function
    expect(decode(input)).toBeTruthy();
  });

  it("should properly type SanitizerOptions", () => {
    const options: SanitizerOptions = {
      allowedTags: ["div", "p"],
      allowedAttributes: {
        div: ["class"],
        "*": ["id"],
      },
    };
    expect(sanitize('<div class="test">content</div>', options)).toBeTruthy();
  });

  it("should properly type Sanitizer interface", () => {
    const customSanitizer: Sanitizer = {
      sanitize: (html: string) => {
        return html; // Simple pass-through for type checking
      },
    };
    expect(customSanitizer.sanitize("<div>test</div>")).toBeTruthy();
  });
});
