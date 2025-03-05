import { describe, it, expect } from "vitest";
import { encode, decode } from "../src/utils/htmlEntities";

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
      // Test entity that would throw on parseInt
      expect(decode("&#xFFFFFFFFFFFFFFFFFF;")).toBe("&#xFFFFFFFFFFFFFFFFFF;");
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
});
