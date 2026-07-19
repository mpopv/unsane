import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { sanitize } from "./htmlSanitizer.js";

function browserBody(html: string): string {
  return new JSDOM(`<body>${html}</body>`).window.document.body.innerHTML;
}

function browserTree(html: string): string {
  const body = new JSDOM(`<body>${html}</body>`).window.document.body;
  return JSON.stringify(
    Array.from(body.childNodes, function describe(node): unknown {
      if (node.nodeType === node.TEXT_NODE) return ["#text", node.textContent];
      return [
        node.nodeName.toLowerCase(),
        Array.from(node.childNodes, describe),
      ];
    }),
  );
}

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

  it("keeps hostile output inert after browser reparsing", () => {
    const hostileInputs = [
      "a<!-- <img src=x onerror=alert(1)> -->b",
      '<svg><a href="javascript:alert(1)">link</a></svg><p>ok</p>',
      "<div><table><tr><td><img src=x onerror=alert(1)></td></tr></table></div>",
      '<a href="java\nscript:alert(1)" target="_blank">link</a>',
      "<math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>",
    ];

    for (const input of hostileInputs) {
      const reparsed = browserBody(sanitize(input));

      expect(reparsed).not.toMatch(/<script\b/i);
      expect(reparsed).not.toMatch(/<svg\b/i);
      expect(reparsed).not.toMatch(/<math\b/i);
      expect(reparsed).not.toMatch(/\son[a-z]+\s*=/i);
      expect(reparsed).not.toMatch(/\s(?:href|src)=["']?\s*javascript:/i);
    }
  });

  it("does not let self-closing syntax keep non-void elements open in browsers", () => {
    const input = '<a href="https://example.com"/>Trusted account settings';
    const sanitized = sanitize(input);

    expect(sanitized).toBe(
      '<a href="https://example.com"></a>Trusted account settings',
    );
    expect(browserBody(sanitized)).toBe(sanitized);

    const document = new JSDOM(`<body>${sanitized}</body>`).window.document;
    expect(document.querySelector("a")?.textContent).toBe("");
    expect(document.body.textContent).toBe("Trusted account settings");
  });

  it("repairs optional paragraph and heading end tags like browsers", () => {
    const input =
      "<p>intro<h2>heading<h3>next</h3>tail<p>second<div>block</div>after";
    const output = sanitize(input);

    expect(output).toBe(
      "<p>intro</p><h2>heading</h2><h3>next</h3>tail<p>second</p><div>block</div>after",
    );
    expect(browserTree(output)).toBe(browserTree(input));
  });

  it("repairs list items without closing items in an outer list scope", () => {
    const input =
      "<ul><li>one<li>two<ul><li>inner<li>next</ul><li>three</ul>";
    const output = sanitize(input);

    expect(output).toBe(
      "<ul><li>one</li><li>two<ul><li>inner</li><li>next</li></ul></li><li>three</li></ul>",
    );
    expect(browserTree(output)).toBe(browserTree(input));
  });

  it("repairs rows and cells into a browser-stable table tree", () => {
    const input = "<table><tr><td>a<td>b<tr><th>c<td>d</table>";
    const output = sanitize(input);

    expect(output).toBe(
      "<table><tr><td>a</td><td>b</td></tr><tr><th>c</th><td>d</td></tr></table>",
    );
    expect(browserTree(output)).toBe(browserTree(input));
  });

  it("repairs definition lists and table sections for custom safe policies", () => {
    const input =
      "<dl><dt>term<dd>definition<dt>next</dl>" +
      "<table><thead><tr><th>h<tbody><tr><td>b<tfoot><tr><td>f</table>";
    const options = {
      allowedTags: [
        "dl",
        "dt",
        "dd",
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
        "th",
        "td",
      ],
      allowedAttributes: {},
    };
    const output = sanitize(input, options);

    expect(browserTree(output)).toBe(browserTree(input));
  });
});
