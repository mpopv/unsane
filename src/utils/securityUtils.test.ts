import { describe, it, expect } from "vitest";
import {
  containsDangerousContent,
  ALLOWED_PROTOCOLS,
  DANGEROUS_CONTENT,
  isSafeUrlAttributeValue,
  isUrlAttribute,
} from "./securityUtils.js";

describe("Security Utils", () => {
  describe("isUrlAttribute", () => {
    it("should identify URL-bearing attributes", () => {
      expect(isUrlAttribute("href")).toBe(true);
      expect(isUrlAttribute("SRC")).toBe(true);
      expect(isUrlAttribute("xlink:href")).toBe(true);
      expect(isUrlAttribute("data-test")).toBe(false);
    });
  });

  describe("isSafeUrlAttributeValue", () => {
    it("should allow empty values, relative URLs, fragments, and allowed protocols", () => {
      expect(isSafeUrlAttributeValue("")).toBe(true);
      expect(isSafeUrlAttributeValue("/docs?q=alert(1)")).toBe(true);
      expect(isSafeUrlAttributeValue("./docs")).toBe(true);
      expect(isSafeUrlAttributeValue("../docs")).toBe(true);
      expect(isSafeUrlAttributeValue("#section")).toBe(true);

      for (const protocol of ALLOWED_PROTOCOLS) {
        expect(isSafeUrlAttributeValue(`${protocol}//example.com`)).toBe(true);
      }
    });

    it("should reject protocol-relative URLs and disallowed protocols", () => {
      expect(isSafeUrlAttributeValue("//example.com/path")).toBe(false);
      expect(isSafeUrlAttributeValue("&#47&#47example.com/path")).toBe(false);
      expect(isSafeUrlAttributeValue("javascript:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("data:text/plain,hello")).toBe(false);
      expect(isSafeUrlAttributeValue("vbscript:msgbox(1)")).toBe(false);
      expect(isSafeUrlAttributeValue("unknown:thing")).toBe(false);
      expect(isSafeUrlAttributeValue("/docs/custom:thing")).toBe(true);
    });

    it("should decode entity-obfuscated protocols before checking", () => {
      expect(isSafeUrlAttributeValue("j&#97;vascript:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("&#104;ttps://example.com")).toBe(true);
      expect(isSafeUrlAttributeValue("javascript&#58;void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("jav&#x09;ascript:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("java&tab;script:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("java&nbsp;script:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("https://example.com/a&nbsp;b")).toBe(
        true,
      );
      expect(isSafeUrlAttributeValue("https://example.com/a&tab;b")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("&#106;avascript:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("&#106avascript:void(0)")).toBe(false);
      expect(
        isSafeUrlAttributeValue(
          "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A;void(0)",
        ),
      ).toBe(false);
      expect(isSafeUrlAttributeValue("javascript&colon;void(0)")).toBe(false);
      expect(
        isSafeUrlAttributeValue(
          `javascript&${"amp;".repeat(7)}colon;void(0)`,
        ),
      ).toBe(false);
    });

    it("should keep recursive entity decoding within its fixed bound", () => {
      let encodedColon = "&colon;";

      for (let layer = 0; layer < 8; layer++) {
        encodedColon = `&amp;${encodedColon.slice(1)}`;
      }

      expect(
        isSafeUrlAttributeValue(`javascript${encodedColon}alert(1)`),
      ).toBe(true);

      expect(
        isSafeUrlAttributeValue(
          `javascript&amp;${encodedColon.slice(1)}alert(1)`,
        ),
      ).toBe(true);
    });

    it("should reject control and unicode obfuscation characters", () => {
      expect(isSafeUrlAttributeValue("java\tscript:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("java script:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("h t t p s ://example.com")).toBe(true);
      expect(isSafeUrlAttributeValue("javascript\u200C:void(0)")).toBe(false);
      expect(isSafeUrlAttributeValue("https://example.com/\u0001x")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/\u007Fx")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/\u009Fx")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/\u200Cx")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/\u200Dx")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/\u200Fx")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/\uFEFFx")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/&#127;x")).toBe(
        false,
      );
      expect(isSafeUrlAttributeValue("https://example.com/&#159;x")).toBe(
        false,
      );
    });

    it("should leave unknown or invalid entities inert", () => {
      expect(isSafeUrlAttributeValue("https://example.com/&madeup;/x")).toBe(
        true,
      );
      expect(
        isSafeUrlAttributeValue("https://example.com/&#999999999;/x"),
      ).toBe(true);
      expect(isSafeUrlAttributeValue("https://example.com/&#999999999/x")).toBe(
        true,
      );
      expect(isSafeUrlAttributeValue("https://example.com/&#xD800;/x")).toBe(
        true,
      );
    });
  });

  describe("containsDangerousContent", () => {
    it("should handle empty or invalid input", () => {
      expect(containsDangerousContent("")).toBe(false);
      expect(containsDangerousContent(null as unknown as string)).toBe(false);
      expect(containsDangerousContent(undefined as unknown as string)).toBe(
        false,
      );
    });

    it("should detect dangerous protocols", () => {
      // Test all allowed protocols
      for (const protocol of ALLOWED_PROTOCOLS) {
        expect(containsDangerousContent(`${protocol}//example.com`)).toBe(
          false,
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
        true,
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
      expect(containsDangerousContent("/docs/custom:thing")).toBe(false);
      expect(containsDangerousContent("Regular text with numbers 123")).toBe(
        false,
      );
    });
  });
});
