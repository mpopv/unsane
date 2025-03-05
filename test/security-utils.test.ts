import { describe, it, expect } from "vitest";
import {
  containsDangerousContent,
  sanitizeTextContent,
  ALLOWED_PROTOCOLS,
  EncodeOptions,
  DANGEROUS_CONTENT,
} from "../src/utils/securityUtils";

describe("Security Utils", () => {
  describe("containsDangerousContent", () => {
    it("should handle empty or invalid input", () => {
      expect(containsDangerousContent("")).toBe(false);
      expect(containsDangerousContent(null as unknown as string)).toBe(false);
      expect(containsDangerousContent(undefined as unknown as string)).toBe(
        false
      );
    });

    it("should detect dangerous protocols", () => {
      // Test all allowed protocols
      for (const protocol of ALLOWED_PROTOCOLS) {
        expect(containsDangerousContent(`${protocol}//example.com`)).toBe(
          false
        );
      }

      // Test dangerous protocols
      expect(containsDangerousContent("javascript:alert(1)")).toBe(true);
      expect(containsDangerousContent("data:text/html,<script>")).toBe(true);
      expect(containsDangerousContent("vbscript:msgbox")).toBe(true);
    });

    it("should detect dangerous content patterns", () => {
      // Test each pattern from DANGEROUS_CONTENT array
      for (const pattern of DANGEROUS_CONTENT) {
        console.log(`Testing pattern: "${pattern}"`);
        const result = containsDangerousContent(pattern);
        console.log(`Result for "${pattern}": ${result}`);
        expect(containsDangerousContent(pattern)).toBe(true);
        // Also test with content around it if it doesn't end with special chars
        if (
          !pattern.endsWith("(") &&
          !pattern.endsWith("=") &&
          !pattern.endsWith(".")
        ) {
          expect(containsDangerousContent(`x${pattern}x`)).toBe(true);
        }
      }

      // Test some variations
      expect(containsDangerousContent("javascript:void(0)")).toBe(true);
      expect(containsDangerousContent("eval('alert(1)')")).toBe(true);
      expect(containsDangerousContent("new Function('return true')")).toBe(
        true
      );
      expect(containsDangerousContent("setTimeout(function(){})")).toBe(true);
      expect(containsDangerousContent("setInterval(callback)")).toBe(true);
    });

    it("should detect dangerous event handlers", () => {
      expect(containsDangerousContent("onerror=alert(1)")).toBe(true);
      expect(containsDangerousContent("onclick=evil()")).toBe(true);
      expect(containsDangerousContent("onload=hack()")).toBe(true);
      expect(containsDangerousContent("onmouseover=pwn()")).toBe(true);
    });

    it("should detect control characters and unicode obfuscation", () => {
      // Control characters
      expect(containsDangerousContent("Hello\u0000World")).toBe(true);
      expect(containsDangerousContent("Test\u001FChar")).toBe(true);
      expect(containsDangerousContent("Bad\u007FChar")).toBe(true);
      expect(containsDangerousContent("Control\u009FChar")).toBe(true);

      // Unicode obfuscation
      expect(containsDangerousContent(String.fromCodePoint(0x200c))).toBe(true); // Zero-width non-joiner
      expect(containsDangerousContent(String.fromCodePoint(0x200d))).toBe(true); // Zero-width joiner
      expect(containsDangerousContent(String.fromCodePoint(0xfeff))).toBe(true); // Zero-width no-break space
      expect(containsDangerousContent("\\u0000")).toBe(true);
    });

    it("should allow safe content", () => {
      expect(containsDangerousContent("Hello World")).toBe(false);
      expect(containsDangerousContent("https://example.com")).toBe(false);
      expect(containsDangerousContent("mailto:user@example.com")).toBe(false);
      expect(containsDangerousContent('<div class="test">')).toBe(false);
      expect(containsDangerousContent("Regular text with numbers 123")).toBe(
        false
      );
    });
  });

  describe("sanitizeTextContent", () => {
    it("should handle empty or invalid input", () => {
      expect(sanitizeTextContent("")).toBe("");
      expect(sanitizeTextContent(null as unknown as string)).toBe("");
      expect(sanitizeTextContent(undefined as unknown as string)).toBe("");
    });

    it("should sanitize dangerous patterns with default encoder", () => {
      expect(sanitizeTextContent("javascript:alert(1)")).toBe(
        "javascript:alert(1)"
      );
      expect(sanitizeTextContent("<script>alert(1)</script>")).toBe(
        "<script>alert(1)</script>"
      );
      expect(sanitizeTextContent("onclick=evil()")).toBe("onclick=evil()");
    });

    it("should use custom encoder to encode dangerous patterns", () => {
      const mockEncoder = (s: string) => `[ENCODED:${s}]`;
      const input = "javascript:alert(1)";
      const output = sanitizeTextContent(input, mockEncoder);
      expect(output).toBe("[ENCODED:javascript]:[ENCODED:alert](1)");
    });

    it("should handle encoder options for dangerous patterns", () => {
      const mockEncoder = (s: string, o?: EncodeOptions) =>
        o?.useNamedReferences ? `[NAMED:${s}]` : `[HEX:${s}]`;
      const input = "javascript:alert(1)";
      const output = sanitizeTextContent(input, mockEncoder);
      expect(output).toBe("[NAMED:javascript]:[NAMED:alert](1)");
    });

    it("should preserve safe content", () => {
      const mockEncoder = (s: string) => `[ENCODED:${s}]`;

      expect(sanitizeTextContent("Hello World", mockEncoder)).toBe(
        "Hello World"
      );
      expect(sanitizeTextContent("Regular text 123", mockEncoder)).toBe(
        "Regular text 123"
      );
      expect(sanitizeTextContent("<div>Safe HTML</div>", mockEncoder)).toBe(
        "<div>Safe HTML</div>"
      );
    });
  });
});
