import { describe, it, expect } from "vitest";
import { sanitize } from "../src/sanitizer/htmlSanitizer";

describe("HTML Sanitizer Edge Cases", () => {
  describe("Nested Structure Handling", () => {
    it("should handle div inside p tag correctly", () => {
      const input = "<p>text<div>inside</div>after</p>";
      const output = sanitize(input);
      expect(output).toBe("<p>text</p><div>inside</div>after");
    });

    it("should handle multiple nested invalid structures", () => {
      const input = "<p>1<div>2<p>3<div>4</div>5</p>6</div>7</p>";
      const output = sanitize(input);
      expect(output).toBe("<p>1</p><div>2<p>3</p><div>4</div>56</div>7");
    });
  });

  describe("Text Content Edge Cases", () => {
    it("should handle control characters in text", () => {
      const input = "<div>Hello\x00World\x1FTest</div>";
      const output = sanitize(input);
      expect(output).toBe("<div>HelloWorldTest</div>");
    });

    it("should handle unicode control characters", () => {
      const input = "<div>Test\u200CZero\u200DWidth\u200EChars</div>";
      const output = sanitize(input);
      expect(output).toBe("<div>Test\u200CZero\u200DWidth\u200EChars</div>");
    });

    it("should preserve whitespace-only text nodes", () => {
      const input = "<div>Hello</div> <div>World</div>";
      const output = sanitize(input);
      expect(output).toBe("<div>Hello</div> <div>World</div>");
    });
  });

  describe("Attribute Security", () => {
    it("should handle dangerous attribute patterns", () => {
      const input =
        '<div onclick="alert(1)" style="color:red" formaction="javascript:alert(1)">test</div>';
      const output = sanitize(input, {
        allowedTags: ["div"],
        allowedAttributes: { div: ["class"] },
      });
      expect(output).toBe("<div>test</div>");
    });

    it("should handle dangerous URL schemes in attributes", () => {
      const input = '<a href="javascript:alert(1)">test</a>';
      const output = sanitize(input, {
        allowedTags: ["a"],
        allowedAttributes: { a: ["href"] },
      });
      expect(output).toBe("<a>test</a>");
    });

    it("should handle attributes with suspicious content", () => {
      const input =
        '<div data-test="javascript:alert(1)" title="alert(document.cookie)">test</div>';
      const output = sanitize(input, {
        allowedTags: ["div"],
        allowedAttributes: { div: ["data-test", "title"] },
      });
      expect(output).toBe("<div>test</div>");
    });

    it("should handle attributes with unicode escapes", () => {
      const input = '<div title="Hello\u200CWorld">test</div>';
      const output = sanitize(input, {
        allowedTags: ["div"],
        allowedAttributes: { div: ["title"] },
      });
      expect(output).toBe("<div>test</div>");
    });
  });

  describe("Tag Structure Edge Cases", () => {
    it("should handle unclosed tags properly", () => {
      const input = "<div><p>test<div>nested</div>";
      const output = sanitize(input);
      expect(output).toBe("<div><p>test</p><div>nested</div></div>");
    });

    it("should handle self-closing tags correctly", () => {
      const input = '<div><img src="test.jpg"><br><hr></div>';
      const output = sanitize(input, {
        allowedTags: ["div", "img", "br", "hr"],
        allowedAttributes: { img: ["src"] },
      });
      expect(output).toBe('<div><img src="test.jpg" /><br /><hr /></div>');
    });

    it("should handle script tags and content", () => {
      const input = "<div>before<script>alert(1)</script>after</div>";
      const output = sanitize(input);
      expect(output).toBe("<div>before>after</div>");
    });
  });

  it("should handle malformed tags and attributes", () => {
    // Test malformed opening tag - sanitizer strips invalid tags
    expect(sanitize("<a<b>test</b>")).toBe("test");

    // Test malformed attributes
    expect(sanitize('<div ="value">test</div>')).toBe("<div>test</div>");
    // Test unclosed quote - sanitizer should treat as text
    expect(sanitize('<div attr=">test</div>')).toBe("");
    // Test unclosed attribute value
    expect(sanitize('<div attr="value>test</div>')).toBe("");

    // Test unquoted attribute values - sanitizer strips non-allowed attributes
    expect(sanitize("<div attr=value>test</div>")).toBe("<div>test</div>");

    // Test self-closing without space
    expect(sanitize("<div/>test")).toBe("<div />test");

    // Test boolean attributes - need to be in allowedAttributes
    expect(
      sanitize("<div checked disabled>test</div>", {
        allowedTags: ["div"],
        allowedAttributes: { div: ["checked", "disabled"] },
      })
    ).toBe("<div checked disabled>test</div>");
  });

  it("should handle edge cases in attribute values", () => {
    // Test empty attribute values - sanitizer strips empty attributes by default
    expect(sanitize('<div attr="">test</div>')).toBe("<div>test</div>");

    // Test whitespace in attribute values - sanitizer strips attributes not in allowlist
    expect(sanitize('<div attr = "value">test</div>')).toBe("<div>test</div>");

    // Test multiple spaces between attributes - only allowed attributes are preserved without values
    expect(
      sanitize('<div  class  =  "value1"   id  =  "value2"  >test</div>')
    ).toBe("<div class id>test</div>");

    // Test allowed attributes with values
    expect(
      sanitize('<div class="c1" id="i1">test</div>', {
        allowedTags: ["div"],
        allowedAttributes: { div: ["class", "id"] },
      })
    ).toBe('<div class="c1" id="i1">test</div>');
  });
});
