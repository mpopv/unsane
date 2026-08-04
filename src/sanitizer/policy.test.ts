import { describe, expect, it } from "vitest";
import { DEFAULT_MAX_INPUT_LENGTH } from "./config.js";
import {
  assertValidInput,
  compilePolicy,
  isAllowedElement,
  serializeAttributes,
} from "./policy.js";
import type { ParsedAttribute } from "./policy.js";
import type { SanitizerOptions } from "../types.js";

describe("sanitizer policy", () => {
  describe("compilePolicy", () => {
    it("compiles the default fail-closed policy once", () => {
      const first = compilePolicy();
      const second = compilePolicy();

      expect(first).toBe(second);
      expect(first.allowedTags).toContain("p");
      expect(first.allowedAttributes.get("*")).toEqual(new Set(["class"]));
      expect(first.maxInputLength).toBe(DEFAULT_MAX_INPUT_LENGTH);
    });

    it("normalizes, merges, and snapshots a custom policy", () => {
      const options = {
        allowedTags: ["DIV", "div"],
        allowedAttributes: {
          DIV: ["CLASS"],
          div: ["DATA-ID"],
        },
        maxInputLength: 42,
      };
      const policy = compilePolicy(options);

      options.allowedTags.length = 0;
      options.allowedAttributes.DIV.length = 0;

      expect(policy.allowedTags).toEqual(new Set(["div"]));
      expect(policy.allowedAttributes.get("div")).toEqual(
        new Set(["class", "data-id"]),
      );
      expect(policy.maxInputLength).toBe(42);
    });

    it.each([
      [null, "Invalid options."],
      [[], "Invalid options."],
      [{ allowedTags: null }, "Invalid allowedTags."],
      [{ allowedTags: ["div", 1] }, "Invalid allowedTags."],
      [{ allowedAttributes: null }, "Invalid allowedAttributes."],
      [{ allowedAttributes: [] }, "Invalid allowedAttributes."],
      [
        { allowedAttributes: { div: "class" } },
        "Invalid allowedAttributes.div.",
      ],
    ])("rejects malformed runtime options %#", (options, message) => {
      expect(() =>
        compilePolicy(options as unknown as SanitizerOptions),
      ).toThrow(message);
    });
  });

  describe("assertValidInput", () => {
    it("accepts bounded input and an explicit infinite limit", () => {
      expect(() => assertValidInput("1234", 4)).not.toThrow();
      expect(() => assertValidInput("12345", Infinity)).not.toThrow();
    });

    it.each([
      [null, 1, "Invalid html."],
      ["x", null, "maxInputLength must be a non-negative number."],
      ["x", -1, "maxInputLength must be a non-negative number."],
      ["x", Number.NaN, "maxInputLength must be a non-negative number."],
      ["12345", 4, "Input length 5 exceeds maxInputLength 4."],
    ])("rejects invalid input bounds %#", (html, limit, message) => {
      expect(() => assertValidInput(html, limit as number)).toThrow(message);
    });
  });

  describe("element capabilities", () => {
    const allowedTags = [
      "base",
      "body",
      "form",
      "head",
      "html",
      "link",
      "meta",
      "widget",
      "x-widget",
      "formx",
    ];
    const policy = compilePolicy({ allowedTags, allowedAttributes: {} });

    it("allows only listed inert element names", () => {
      expect(isAllowedElement("widget", policy)).toBe(true);
      expect(isAllowedElement("formx", policy)).toBe(true);
      expect(isAllowedElement("section", policy)).toBe(false);
      expect(isAllowedElement("x-widget", policy)).toBe(false);

      for (const tagName of [
        "base",
        "body",
        "form",
        "head",
        "html",
        "link",
        "meta",
      ]) {
        expect(isAllowedElement(tagName, policy), tagName).toBe(false);
      }
    });
  });

  describe("attribute capabilities", () => {
    const unsupportedAttributes =
      "accesskey attributionsrc autofocus commandfor form formaction formenctype formmethod formnovalidate formtarget http-equiv imagesrcset is nonce ping popover popovertarget popovertargetaction slot srcdoc srcset style tabindex xmlns".split(
        " ",
      );
    const allowedAttributes = [
      "class",
      "data-note",
      "href",
      "id",
      "rel",
      "target",
      "title",
      "stylex",
      "xlinker",
      "xmlnsx",
      ...unsupportedAttributes,
      "onclick",
      "xlink:href",
      "xmlns:xlink",
    ];
    const policy = compilePolicy({
      allowedTags: ["a", "div"],
      allowedAttributes: {
        a: allowedAttributes,
        "*": ["class"],
      },
    });

    function serialize(attributes: ParsedAttribute[], tagName = "a"): string {
      return serializeAttributes(attributes, tagName, policy);
    }

    it("keeps allowlisted inert values and the first duplicate", () => {
      expect(
        serialize([
          ["title", "one &amp; two", true],
          ["title", "drop", true],
          ["class", "notice", true],
          ["id", "scoped", true],
          ["data-note", "", false],
          ["unknown", "drop", true],
        ]),
      ).toBe(' title="one &amp; two" class="notice" id="scoped" data-note');
    });

    it("rejects every unsupported attribute family while preserving near misses", () => {
      const attributes: ParsedAttribute[] = [
        ...unsupportedAttributes.map(
          (name): ParsedAttribute => [name, "active", true],
        ),
        ["onclick", "active", true],
        ["xlink:href", "/active", true],
        ["xmlns:xlink", "/active", true],
        ["stylex", "safe", true],
        ["xlinker", "safe", true],
        ["xmlnsx", "safe", true],
      ];

      expect(serialize(attributes)).toBe(
        ' stylex="safe" xlinker="safe" xmlnsx="safe"',
      );
    });

    it("validates URL-bearing attributes after entity decoding", () => {
      expect(
        serialize([
          ["href", "https://example.com/?a=1&amp;b=2", true],
          ["href", "javascript:alert(1)", true],
        ]),
      ).toBe(' href="https://example.com/?a=1&amp;b=2"');
      expect(serialize([["href", "javascript&#58;alert(1)", true]])).toBe("");
    });

    it("drops controls from inert attributes instead of keyword filtering", () => {
      expect(
        serialize([
          ["title", "javascript:alert(1)", true],
          ["data-note", "bad\u0000value", true],
        ]),
      ).toBe(' title="javascript:alert(1)"');
    });

    it("constrains targets and hardens blank links", () => {
      expect(
        serialize([
          ["href", "/docs", true],
          ["target", " _BLANK ", true],
          ["rel", "opener NOFOLLOW noopener", true],
        ]),
      ).toBe(
        ' href="/docs" target="_blank" rel="nofollow noopener noreferrer"',
      );
      expect(serialize([["target", "_blank", true]])).toBe(
        ' target="_blank" rel="noopener noreferrer"',
      );
      expect(serialize([["target", " _SELF ", true]])).toBe(' target="_self"');
      expect(serialize([["target", "named", true]])).toBe("");
      expect(serialize([["target", "", false]])).toBe(" target");
    });

    it("does not attach link relations to non-anchor targets", () => {
      expect(serialize([["class", "notice", true]], "div")).toBe(
        ' class="notice"',
      );
    });
  });
});
