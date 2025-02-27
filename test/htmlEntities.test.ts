import { describe, it, expect } from "vitest";
import { decode, encode, escape } from "../src/unsane";

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
      expect(decode("&lt")).toBe("&lt"); // No semicolon
      expect(decode("&unknown;")).toBe("&unknown;"); // Unknown entity
      expect(decode("&#xGHI;")).toBe("&#xGHI;"); // Invalid hex
      expect(decode("&#abc;")).toBe("&#abc;"); // Invalid decimal
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
        "&lt;img src=&quot;x&quot; onerror=&quot;alert(&apos;XSS&apos;)&quot;&gt;"
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