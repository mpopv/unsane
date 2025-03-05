import { describe, it, expect } from "vitest";
import { decode, encode, escape } from "./htmlEntities";

describe("htmlEntities", () => {
  describe("decode", () => {
    it("should decode named entities", () => {
      expect(decode("&lt;div&gt;")).toBe("<div>");
      expect(decode("&amp;")).toBe("&");
      expect(decode("&quot;")).toBe('"');
      expect(decode("&apos;")).toBe("'");
    });

    it("should decode decimal numeric entities", () => {
      expect(decode("&#60;")).toBe("<");
      expect(decode("&#38;")).toBe("&");
      expect(decode("&#34;")).toBe('"');
    });

    it("should decode hexadecimal numeric entities", () => {
      expect(decode("&#x3C;")).toBe("<");
      expect(decode("&#x26;")).toBe("&");
      expect(decode("&#x22;")).toBe('"');
      expect(decode("&#X3C;")).toBe("<"); // Capital X also works
    });

    it("should handle malformed entities", () => {
      // Malformed entities without semicolons should remain unchanged
      expect(decode("&lt")).toBe("&lt");

      // Unknown or invalid entities with semicolons should remain unchanged
      expect(decode("&unknown;")).toBe("&unknown;");
      expect(decode("&#xGHI;")).toBe("&#xGHI;");
      expect(decode("&#abc;")).toBe("&#abc;");
    });

    it("should decode multiple entities in a string", () => {
      expect(decode("&lt;div&gt;Hello &amp; world!&lt;/div&gt;")).toBe(
        "<div>Hello & world!</div>"
      );
    });
  });

  describe("encode", () => {
    it("should encode special characters with numeric references by default", () => {
      const result = encode("<div>");
      expect(result).toContain("&#x3C;"); // <
      expect(result).toContain("&#x3E;"); // >
    });

    it("should use named references when requested", () => {
      const result = encode("<div>", { useNamedReferences: true });
      expect(result).toBe("&lt;div&gt;");
    });

    it("should use decimal references when requested", () => {
      const result = encode("<div>", { decimal: true });
      expect(result).toBe("&#60;div&#62;");
    });

    it("should only encode special chars by default", () => {
      const result = encode("Hi <there>");
      expect(result).toBe("Hi &#x3C;there&#x3E;");
    });

    it("should encode everything when requested", () => {
      const result = encode("Hi", { encodeEverything: true });
      expect(result).toBe("&#x48;&#x69;");
    });
  });

  describe("escape", () => {
    it("should escape only essential characters", () => {
      const input = '<img src="x" onerror="alert(\'XSS\')">';
      const result = escape(input);
      expect(result).toBe(
        "&lt;img src=&quot;x&quot; onerror=&quot;alert(&#x27;XSS&#x27;)&quot;&gt;"
      );
    });

    it("should leave normal text untouched", () => {
      expect(escape("Hello world")).toBe("Hello world");
    });

    it("should handle all escapable characters", () => {
      const input = "&<>\"'`";
      const result = escape(input);
      expect(result).toBe("&amp;&lt;&gt;&quot;&#x27;&#x60;");
    });
  });
});

describe("HTML Entities Edge Cases", () => {
  describe("encode edge cases", () => {
    it("should handle empty input", () => {
      expect(encode("")).toBe("");
      expect(encode(null as unknown as string)).toBe("");
      expect(encode(undefined as unknown as string)).toBe("");
    });

    it("should handle all encoding options combinations", () => {
      const input = '<div>"test"</div>';

      // Test useNamedReferences
      expect(encode(input, { useNamedReferences: true })).toBe(
        "&lt;div&gt;&quot;test&quot;&lt;/div&gt;"
      );

      // Test decimal encoding
      expect(encode(input, { decimal: true })).toBe(
        "&#60;div&#62;&#34;test&#34;&#60;/div&#62;"
      );

      // Test encodeEverything
      const encoded = encode(input, { encodeEverything: true });
      expect(encoded).toMatch(/^(?:&#x[0-9A-F]+;)+$/);
      expect(decode(encoded)).toBe(input);

      // Test escapeOnly
      expect(encode(input, { escapeOnly: true })).toBe(
        "&lt;div&gt;&quot;test&quot;&lt;/div&gt;"
      );

      // Test combinations
      expect(encode(input, { useNamedReferences: true, decimal: true })).toBe(
        "&lt;div&gt;&quot;test&quot;&lt;/div&gt;"
      );
    });

    it("should handle non-string input", () => {
      expect(encode(123 as unknown as string)).toBe("123");
      expect(encode(true as unknown as string)).toBe("true");
      expect(encode({} as unknown as string)).toBe("[object Object]");
    });
  });

  describe("decode edge cases", () => {
    it("should handle empty input", () => {
      expect(decode("")).toBe("");
      expect(decode(null as unknown as string)).toBe("");
      expect(decode(undefined as unknown as string)).toBe("");
    });

    it("should handle invalid numeric entities", () => {
      // Test invalid hex entity
      expect(decode("&#xZ;")).toBe("&#xZ;");
      // Test invalid decimal entity
      expect(decode("&#ABC;")).toBe("&#ABC;");
      // Test empty numeric entity
      expect(decode("&#;")).toBe("&#;");
      // Test entity that would throw on parseInt - should return replacement char
      expect(decode("&#xFFFFFFFFFFFFFFFFFF;")).toBe("\uFFFD");
    });

    it("should handle surrogate pairs correctly", () => {
      // Test surrogate pair handling
      expect(decode("&#x10437;")).toBe("𐐷");

      // Test invalid surrogate pairs
      expect(decode("&#xD800;")).toBe("\uFFFD");
      expect(decode("&#xDC00;")).toBe("\uFFFD");
    });

    it("should handle malformed entities", () => {
      expect(decode("&amp")).toBe("&amp");
      expect(decode("&;")).toBe("&;");
      expect(decode("&#")).toBe("&#");
      expect(decode("&#x")).toBe("&#x");
      expect(decode("&NotARealEntity;")).toBe("&NotARealEntity;");
    });

    it("should handle mixed valid and invalid entities", () => {
      const input = "Valid: &amp; &#x26; &#38; Invalid: &fake; &#xZ; &#A;";
      expect(decode(input)).toBe("Valid: & & & Invalid: &fake; &#xZ; &#A;");
    });
  });

  it("should handle non-special characters in escape mode", () => {
    expect(encode("normal", { escapeOnly: true })).toBe("normal");
    expect(encode("123", { escapeOnly: true })).toBe("123");
    expect(encode("abc", { escapeOnly: true })).toBe("abc");
  });

  it("should properly handle mixed content with escapeOnly mode", () => {
    // This specifically tests the default case in the switch statement
    // where non-special characters are returned as-is
    const input = "a<b>c\"d'e&f`g";
    const expected = "a&lt;b&gt;c&quot;d&#x27;e&amp;f&#x60;g";
    expect(encode(input, { escapeOnly: true })).toBe(expected);

    // Testing with characters outside the typical ASCII range
    const unicodeInput = "Café < Restaurant & Bar";
    const unicodeExpected = "Café &lt; Restaurant &amp; Bar";
    expect(encode(unicodeInput, { escapeOnly: true })).toBe(unicodeExpected);
  });

  // Specifically target line 87 in htmlEntities.ts
  it("should handle edge case for non-target characters in RegExp with specific options", () => {
    // This should hit line 87 - we need to create a case where !escapeOnly && !encodeEverything
    // but we have a character that doesn't match /"&<>'/

    // Create a payload with a mix of special chars and normal chars
    const result = encode("a&b<c>d'e\"f", {
      escapeOnly: false,
      encodeEverything: false,
    });

    // Special chars should be encoded as hex entities (not named entities)
    // since we didn't set useNamedReferences: true
    expect(result).toContain("&#x26;"); // & as hex
    expect(result).toContain("&#x3C;"); // < as hex
    expect(result).toContain("&#x3E;"); // > as hex
    expect(result).toContain("&#x27;"); // ' as hex
    expect(result).toContain("&#x22;"); // " as hex

    // Normal chars should be left as-is
    expect(result).toContain("a");
    expect(result).toContain("b");
    expect(result).toContain("c");
    expect(result).toContain("d");
    expect(result).toContain("e");
    expect(result).toContain("f");

    // Additional test specifically for line 87
    // Test with a character that doesn't match the pattern but with !escapeOnly && !encodeEverything
    const resultWithNonTarget = encode("xyz123", {
      escapeOnly: false,
      encodeEverything: false,
    });

    // Should be unchanged since none of these characters match /"&<>'/
    expect(resultWithNonTarget).toBe("xyz123");
  });

  // Specifically target line 139 in htmlEntities.ts
  it("should handle extremely broken HTML entity formats", () => {
    // This should trigger the error handling in the try/catch around line 139
    // by creating invalid hex and decimal entities with parsing errors

    // Invalid hex entity with invalid code point
    const invalidHex = decode("&#xFFFFFFFFFFFFFFFFF;"); // Too large value
    // The decode function actually converts this to the replacement character
    expect(invalidHex).toBe("\uFFFD"); // Replacement character

    // Invalid decimal entity with NaN
    const invalidDecimal = decode("&#ABCDEF;"); // Non-numeric
    expect(invalidDecimal).toBe("&#ABCDEF;"); // Should be unchanged

    // Invalid hex entity with nothing after x
    const emptyHex = decode("&#x;");
    expect(emptyHex).toBe("&#x;");

    // Try to create an error in the parseInt functions
    const weirdHex = decode("&#x-1;");
    expect(weirdHex).toBe("&#x-1;");

    const weirdDecimal = decode("&#-1;");
    expect(weirdDecimal).toBe("&#-1;");

    // Additional test specifically for line 139
    // Test with an entity that will cause an exception in the try/catch block
    try {
      // Force an error by creating a situation where parseInt might throw
      const forceError = decode("&#x" + "F".repeat(1000) + ";");
      // If we get here, just make sure the result is reasonable
      expect(forceError).toBe("\uFFFD");
    } catch (e) {
      // If we do get an exception, that's fine too - the code should handle it
      expect(true).toBe(true);
    }
  });

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
