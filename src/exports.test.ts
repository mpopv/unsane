import { describe, it, expect } from "vitest";
import { createSanitizer, sanitize, escape, encode, decode } from "./index.js";
import type {
  CompiledSanitizer,
  EncodeOptions,
  SanitizerOptions,
} from "./index.js";

describe("Library exports", () => {
  it("should export all required functions", () => {
    expect(typeof sanitize).toBe("function");
    expect(typeof createSanitizer).toBe("function");
    expect(typeof escape).toBe("function");
    expect(typeof encode).toBe("function");
    expect(typeof decode).toBe("function");
  });

  it("should have correct function signatures", () => {
    const input = "<div>test</div>";

    // Test sanitize function
    expect(sanitize(input)).toBe("<div>test</div>");
    expect(sanitize(input, {})).toBe("<div>test</div>");
    expect(sanitize(input, { allowedTags: ["div"] })).toBe("<div>test</div>");

    // Test escape function
    expect(escape(input)).toBe("&lt;div&gt;test&lt;/div&gt;");

    // Test encode function
    expect(encode(input)).toBe("&#x3C;div&#x3E;test&#x3C;/div&#x3E;");

    // Test decode function
    expect(decode(input)).toBe(input);
  });

  it("should properly type SanitizerOptions", () => {
    const options: SanitizerOptions = {
      allowedTags: ["div", "p"],
      allowedAttributes: {
        div: ["class"],
        "*": ["id"],
      },
    };
    expect(sanitize('<div class="test">content</div>', options)).toBe(
      '<div class="test">content</div>',
    );
  });

  it("should export the encoder options type", () => {
    const options: EncodeOptions = { useNamedReferences: true };
    expect(encode("<", options)).toBe("&lt;");
  });

  it("should export the compiled sanitizer type", () => {
    const compiled: CompiledSanitizer = createSanitizer({
      allowedTags: ["p"],
    });
    expect(compiled("<div>drop</div><p>keep</p>")).toBe("drop<p>keep</p>");
  });
});
