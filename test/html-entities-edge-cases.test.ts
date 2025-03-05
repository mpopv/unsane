import { describe, it, expect } from "vitest";
import { encode, decode } from "../src/utils/htmlEntities";

describe("HTML Entities Edge Cases", () => {
  // Test for line 87 in htmlEntities.ts
  it("should handle non-standard characters in encode function", () => {
    // Test with a character that wouldn't normally be encoded
    const inputWithNormalChars = "regular text 123";
    const outputWithEncode = encode(inputWithNormalChars, {
      encodeEverything: true,
    });
    // When encodeEverything is true, even normal characters should be encoded
    expect(outputWithEncode).not.toBe(inputWithNormalChars);

    // Test non-target characters with escapeOnly flag
    const output = encode("Hello World", { escapeOnly: true });
    expect(output).toBe("Hello World"); // No special chars, so no encoding

    // Test both flags at once to hit specific branch
    const specialOutput = encode("a&b<c>d'e\"f", {
      escapeOnly: true,
      encodeEverything: false,
    });
    expect(specialOutput).not.toBe("a&b<c>d'e\"f");
    expect(specialOutput).toContain("&lt;"); // < encoded
  });

  // Test for line 139 in htmlEntities.ts
  it("should handle edge cases in HTML entity decoding", () => {
    // Test with invalid hex entity that could trigger error path
    const output = decode("&#xZ;"); // Invalid hex entity
    expect(output).toBe("&#xZ;"); // Should return unchanged

    // Test with another invalid numeric entity
    const output2 = decode("&#;"); // Invalid numeric entity
    expect(output2).toBe("&#;"); // Should return unchanged

    // Mix of valid and invalid entities
    const output3 = decode("Valid: &lt; Invalid: &#xG;");
    expect(output3).toBe("Valid: < Invalid: &#xG;");

    // Test specific code paths for numeric entities
    const output4 = decode("&#X20;"); // Uppercase X should work too
    expect(output4).toBe(" "); // Space character
  });
});
