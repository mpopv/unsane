import { describe, expect, it } from "vitest";
import { sanitize } from "./htmlSanitizer.js";

describe("htmlSanitizer malformed parser corpus", () => {
  it("strips comments without leaking markup inside them", () => {
    expect(sanitize("a<!-- <img src=x onerror=alert(1)> -->b")).toBe("ab");
    expect(sanitize("a<!-- unterminated")).toBe("a");
  });

  it("drops dangerous raw-content containers with their contents", () => {
    expect(sanitize("<style>alert(1)</style><p>ok</p>")).toBe("<p>ok</p>");
    expect(sanitize("<iframe><p>bad</p></iframe><p>ok</p>")).toBe("<p>ok</p>");
    expect(
      sanitize("<template><img src=x onerror=alert(1)></template>ok"),
    ).toBe("ok");
  });

  it("drops SVG and MathML containers rather than partially sanitizing namespaces", () => {
    expect(
      sanitize('<svg><a href="https://example.com">link</a></svg><p>ok</p>'),
    ).toBe("<p>ok</p>");
    expect(sanitize("<math><mi>x</mi></math><p>ok</p>")).toBe("<p>ok</p>");
    expect(sanitize("<svg /><p>ok</p>")).toBe("<p>ok</p>");
  });

  it("deduplicates attributes after the first safe emitted value", () => {
    expect(
      sanitize('<div class="one" class="two" id="x">Text</div>', {
        allowedTags: ["div"],
        allowedAttributes: { div: ["class", "id"] },
      }),
    ).toBe('<div class="one" id="x">Text</div>');

    expect(
      sanitize('<a href="javascript:alert(1)" href="/safe">Link</a>', {
        allowedTags: ["a"],
        allowedAttributes: { a: ["href"] },
      }),
    ).toBe('<a href="/safe">Link</a>');
  });

  it("handles uncommon whitespace and slash placement without creating attributes", () => {
    expect(
      sanitize('<div\u00A0class="x">Text</div>', {
        allowedTags: ["div"],
        allowedAttributes: { div: ["class"] },
      }),
    ).toBe('<div class="x">Text</div>');

    expect(sanitize("<p>one<br/ / / >two</p>")).toBe("<p>one<br />two</p>");
  });

  it("drops unterminated quoted attributes instead of repairing them unsafely", () => {
    expect(sanitize('<div title="unterminated>Text</div>')).toBe("");
  });
});
