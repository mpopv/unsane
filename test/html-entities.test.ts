import { describe, it, expect } from "vitest";
import { decode, encode, escape } from "../src/utils/htmlEntities";

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
});
