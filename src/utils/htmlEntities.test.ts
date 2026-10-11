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
      ["😀\n", { encodeEverything: true }, "&#x1F600;&#xA;"],
      ["😀\r", { encodeEverything: true, decimal: true }, "&#128512;&#13;"],
      ["", {}, ""],
    ])("encodes %j with %j", (input, options, expected) => {
      expect(encode(input, options)).toBe(expected);
    });

    it("round-trips every code point through decode", () => {
      const text = "a\n\t😀𐐷é<&>\"'";

      expect(decode(encode(text, { encodeEverything: true }))).toBe(text);
      expect(
        decode(encode(text, { encodeEverything: true, decimal: true })),
      ).toBe(text);
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

    it("leaves inherited object property names undecoded", () => {
      const input = "&constructor; &toString; &valueOf; &hasOwnProperty;";

      expect(decode(input)).toBe(input);
      expect(normalizeText(input)).toBe(input);
      expect(normalizeAttributeValue(input)).toBe(input);
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
        "&lt;&amp;€�\t&#x60;&gt;",
      );
      expect(normalizeText("\u009f\u00a0")).toBe("\u00a0");
      expect(normalizeAttributeValue("'\"<&madeup;")).toBe(
        "&#x27;&quot;&lt;&madeup;",
      );
    });

    it("keeps HTML whitespace while dropping other controls", () => {
      expect(normalizeText("a\tb\nc\fd\re\r\nf")).toBe("a\tb\nc\fd\re\r\nf");
      expect(normalizeText("&#9;&#10;&#12;&#13;")).toBe("\t\n\f\r");
      expect(normalizeText("a\u0000\u0001\u0008\u000b\u000e\u001fb")).toBe(
        "ab",
      );
    });

    it("applies the attribute-context semicolon omission rule", () => {
      expect(normalizeAttributeValue("&ampx &amp= &amp ")).toBe(
        "&ampx &amp= &amp; ",
      );
    });
  });
});
