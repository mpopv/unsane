import { describe, expect, it } from "vitest";
import {
  decode,
  encode,
  escape,
  normalizeAttributeValue,
  normalizeText,
} from "./htmlEntities.js";

describe("HTML entity helpers", () => {
  describe("encode", () => {
    it.each([
      ["<div>", {}, "&#x3C;div&#x3E;"],
      ["<div>", { useNamedReferences: true }, "&lt;div&gt;"],
      ["<div>", { decimal: true }, "&#60;div&#62;"],
      ["Hi", { encodeEverything: true }, "&#x48;&#x69;"],
      [
        "A<&",
        { encodeEverything: true, useNamedReferences: true },
        "&#x41;&lt;&amp;",
      ],
      ["", {}, ""],
    ])("encodes %j with %j", (input, options, expected) => {
      expect(encode(input, options)).toBe(expected);
    });

    it("stringifies non-string runtime inputs", () => {
      expect(encode(123 as unknown as string)).toBe("123");
      expect(encode(true as unknown as string)).toBe("true");
      expect(encode({} as unknown as string)).toBe("[object Object]");
      expect(encode(null as unknown as string)).toBe("");
    });
  });

  describe("escape", () => {
    it("escapes the complete context-safe character set", () => {
      expect(escape("&<>\"'`")).toBe("&amp;&lt;&gt;&quot;&#x27;&#x60;");
      expect(escape("Café and ordinary text")).toBe("Café and ordinary text");
      expect(escape("")).toBe("");
    });
  });

  describe("decode", () => {
    it.each([
      ["&lt;div&gt;&quot;&apos;&amp;", "<div>\"'&"],
      ["&LT;&GT;&QUOT;&AMP;", '<>"&'],
      ["&lt &amp &quot &nbsp", '< & " \u00A0'],
      ["&apos &unknown; &copy;", "&apos &unknown; &copy;"],
      ["&colon;&NewLine;&Tab;", ":\n\t"],
      ["&#60; &#38; &#34;", '< & "'],
      ["&#x3C; &#X3E;", "< >"],
      ["&#60 &#x3e", "< >"],
      ["&#0; &#128; &#x82; &#x9f;", "� € ‚ Ÿ"],
      ["&#xD800; &#xDFFF; &#x110000;", "� � �"],
      ["&#x10437;", "𐐷"],
      ["&#xFFFFFFFFFFFFFFFFFF;", "�"],
      ["&; &#; &#x; &#xG; &#-1;", "&; &#; &#x; &#xG; &#-1;"],
      ["", ""],
    ])("decodes %j", (input, expected) => {
      expect(decode(input)).toBe(expected);
    });

    it("preserves the inclusive Unicode scalar boundaries", () => {
      expect(decode("&#xFFFF; &#x10FFFF;")).toBe(
        `${String.fromCodePoint(0xffff)} ${String.fromCodePoint(0x10ffff)}`,
      );
    });
  });

  describe("sanitizer normalization", () => {
    it("preserves browser-recognized named references without double decoding", () => {
      expect(normalizeText("&copy; &NotEqualTilde; &amp;copy;")).toBe(
        "&copy; &NotEqualTilde; &amp;copy;",
      );
      expect(normalizeAttributeValue("&copy; &amp;copy; &amp=literal")).toBe(
        "&copy; &amp;copy; &amp=literal",
      );
    });

    it("decodes numeric references before filtering controls and escaping", () => {
      expect(normalizeText("<&amp;&#128;&#0;&#9;&#127;`>")).toBe(
        "&lt;&amp;€�&#x60;&gt;",
      );
      expect(normalizeText("\u009f\u00a0")).toBe("\u00a0");
      expect(normalizeAttributeValue("'\"<&madeup;")).toBe(
        "&#x27;&quot;&lt;&madeup;",
      );
    });

    it("applies the attribute-context semicolon omission rule", () => {
      expect(normalizeAttributeValue("&ampx &amp= &amp ")).toBe(
        "&ampx &amp= &amp; ",
      );
    });
  });
});
