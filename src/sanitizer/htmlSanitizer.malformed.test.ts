import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { sanitize } from "./htmlSanitizer.js";

function browserBody(html: string): string {
  return new JSDOM(`<body>${html}</body>`).window.document.body.innerHTML;
}

type BrowserNode = InstanceType<JSDOM["window"]["Node"]>;

// Describes elements and text; comments are skipped because Unsane drops them.
function browserTree(html: string): string {
  const body = new JSDOM(`<body>${html}</body>`).window.document.body;
  return JSON.stringify(
    (function describe(node: BrowserNode): unknown[] {
      return Array.from(node.childNodes)
        .filter((child) => child.nodeType !== child.COMMENT_NODE)
        .map((child) =>
          child.nodeType === child.TEXT_NODE
            ? ["#text", child.textContent]
            : [child.nodeName.toLowerCase(), describe(child)],
        );
    })(body),
  );
}

describe("htmlSanitizer malformed parser corpus", () => {
  it("strips comments without leaking markup inside them", () => {
    expect(sanitize("a<!-- <img src=x onerror=alert(1)> -->b")).toBe("ab");
    expect(sanitize("a<!-- unterminated")).toBe("a");
  });

  it("ends comments and bogus comments where browsers do", () => {
    for (const input of [
      "<!--><b>after empty comment</b>",
      "<!---><b>after empty comment</b>",
      "<!----><b>after empty comment</b>",
      "<!-- x --!><b>after bang-closed comment</b>",
      "<!-- x --!><b>bang first</b>-->tail",
      "<!-- x --><b>dash first</b> --!> tail",
      "<!--!><b>still a comment</b>-->after",
      "<!---!><b>still a comment</b>-->after",
      "<?xml version='1.0'?><p>after processing instruction</p>",
      "<![CDATA[x]]><p>after CDATA</p>",
      "<!DOCTYPE html><p>after doctype</p>",
    ]) {
      const output = sanitize(input);

      expect(output, input).not.toMatch(/<!|<\?|&lt;[!?]/);
      expect(browserTree(output), input).toBe(browserTree(input));
    }
  });

  it("treats a slash inside a start tag as an attribute separator", () => {
    const options = {
      allowedTags: ["a", "b", "img"],
      allowedAttributes: { a: ["href", "title"], img: ["src"] },
    };

    expect(sanitize('<a/href="https://example.com/">link</a>', options)).toBe(
      '<a href="https://example.com/">link</a>',
    );
    expect(sanitize('<a href="/x"/title="t">link</a>', options)).toBe(
      '<a href="/x" title="t">link</a>',
    );
    expect(sanitize('<img src="x.png"/onerror="alert(1)">', options)).toBe(
      '<img src="x.png" />',
    );
    expect(sanitize("<b/ >text</b>", options)).toBe("<b>text</b>");
    expect(browserTree("<b/ >text</b>")).toBe(browserTree("<b>text</b>"));
  });

  it("keeps a stray '<' as text and reconsumes the next character", () => {
    for (const [input, expected] of [
      ["<<<b>x</b>", "&lt;&lt;<b>x</b>"],
      ["a < b <<b>c</b>", "a &lt; b &lt;<b>c</b>"],
      ["trailing <", "trailing &lt;"],
      ["<", "&lt;"],
    ]) {
      const output = sanitize(input);

      expect(output, input).toBe(expected);
      expect(browserTree(output), input).toBe(browserTree(input));
    }
  });

  it("drops dangerous raw-content containers with their contents", () => {
    expect(sanitize("<style>alert(1)</style><p>ok</p>")).toBe("<p>ok</p>");
    expect(sanitize("<iframe><p>bad</p></iframe><p>ok</p>")).toBe("<p>ok</p>");
    expect(
      sanitize("<template><img src=x onerror=alert(1)></template>ok"),
    ).toBe("ok");
  });

  it("recognizes raw-content end tags only at HTML name boundaries", () => {
    expect(
      sanitize("<script>bad</scriptx><p>still bad</p></ScRiPt ><p>safe</p>"),
    ).toBe("<p>safe</p>");
    expect(
      sanitize("<style>bad</stylesheet><p>still bad</p></style/><p>safe</p>"),
    ).toBe("<p>safe</p>");
    expect(
      sanitize("<textarea>bad</textarea!><p>still bad</p></textarea>safe"),
    ).toBe("safe");
  });

  it("does not treat self-closing syntax as closing HTML raw-text elements", () => {
    expect(sanitize("<textarea/><p>not exposed</p>")).toBe("");
    expect(sanitize("<script/><p>not exposed</p>")).toBe("");
  });

  it("drops SVG and MathML containers rather than partially sanitizing namespaces", () => {
    expect(
      sanitize('<svg><a href="https://example.com">link</a></svg><p>ok</p>'),
    ).toBe("<p>ok</p>");
    expect(sanitize("<math><mi>x</mi></math><p>ok</p>")).toBe("<p>ok</p>");
    expect(sanitize("<svg /><p>ok</p>")).toBe("<p>ok</p>");
  });

  it("keeps only the first occurrence of each attribute like browsers", () => {
    expect(
      sanitize('<div class="one" class="two" id="x">Text</div>', {
        allowedTags: ["div"],
        allowedAttributes: { div: ["class", "id"] },
      }),
    ).toBe('<div class="one" id="x">Text</div>');

    const input = '<a href="javascript:alert(1)" href="/safe">Link</a>';
    const output = sanitize(input, {
      allowedTags: ["a"],
      allowedAttributes: { a: ["href"] },
    });

    expect(output).toBe("<a>Link</a>");
    expect(browserBody(input)).toBe('<a href="javascript:alert(1)">Link</a>');
  });

  it("drops plaintext and everything after it even when allowlisted", () => {
    expect(
      sanitize("<p>a</p><plaintext><b>b</b></plaintext><p>c</p>", {
        allowedTags: ["p", "b", "plaintext"],
        allowedAttributes: {},
      }),
    ).toBe("<p>a</p>");

    const document = new JSDOM("<plaintext><b>b</b>").window.document;
    expect(document.querySelector("b")).toBeNull();
    expect(document.querySelector("plaintext")?.textContent).toBe("<b>b</b>");
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

  it("preserves browser-visible named and numeric reference semantics", () => {
    const input =
      '<p title="&copy; &NotEqualTilde; &amp;copy; &#128; &#0;">' +
      "&copy &NotEqualTilde; &amp;copy; &#128; &#0;</p>";
    const output = sanitize(input, {
      allowedTags: ["p"],
      allowedAttributes: { p: ["title"] },
    });
    const inputDocument = new JSDOM(`<body>${input}</body>`).window.document;
    const outputDocument = new JSDOM(`<body>${output}</body>`).window.document;

    expect(output).toBe(
      '<p title="&copy; &NotEqualTilde; &amp;copy; € �">' +
        "&copy &NotEqualTilde; &amp;copy; € �</p>",
    );
    expect(outputDocument.body.textContent).toBe(
      inputDocument.body.textContent,
    );
    expect(outputDocument.querySelector("p")?.title).toBe(
      inputDocument.querySelector("p")?.title,
    );
    expect(
      sanitize(output, {
        allowedTags: ["p"],
        allowedAttributes: { p: ["title"] },
      }),
    ).toBe(output);
  });

  it("keeps URL references and protocol-relative checks aligned with browsers", () => {
    const options = { allowedTags: ["a"], allowedAttributes: { a: ["href"] } };
    const resolvedHref = (html: string) =>
      new JSDOM(`<body>${html}</body>`, {
        url: "https://app.test/page",
      }).window.document.querySelector("a")?.href;

    const preserved = '<a href="/docs?x=1&sol;2&amp;y=&copy;">x</a>';
    expect(sanitize(preserved, options)).toBe(preserved);
    expect(resolvedHref(sanitize(preserved, options))).toBe(
      resolvedHref(preserved),
    );

    for (const href of ["\\\\evil.test", "/\\evil.test", "\\/evil.test"]) {
      expect(new URL(href, "https://app.test/").host).toBe("evil.test");
      expect(sanitize(`<a href="${href}">x</a>`, options)).toBe("<a>x</a>");
    }

    const ambiguous = sanitize('<a href="/&sol;evil.test">x</a>', options);
    expect(resolvedHref(ambiguous)).toBe("https://app.test/&sol;evil.test");
  });

  it("does not let removed markup or controls merge text into a new reference", () => {
    const options = { allowedTags: ["p"], allowedAttributes: { p: ["title"] } };

    for (const input of [
      "&l<x>t;",
      "&l<!-- -->t;",
      "&l&#116;",
      "<p title='&l&#116;'>&nb<x></x>sp;</p>",
    ]) {
      const output = sanitize(input, options);
      const inputDocument = new JSDOM(`<body>${input}</body>`).window.document;
      const outputDocument = new JSDOM(`<body>${output}</body>`).window
        .document;

      expect(sanitize(output, options), input).toBe(output);
      expect(outputDocument.body.textContent, input).toBe(
        inputDocument.body.textContent,
      );
      expect(outputDocument.querySelector("p")?.title, input).toBe(
        inputDocument.querySelector("p")?.title,
      );
    }

    const withControl = sanitize("&a\u0000mp;");
    expect(withControl).toBe("&amp;amp;");
    expect(sanitize(withControl)).toBe(withControl);
  });

  it("preserves whitespace that browsers keep in text", () => {
    for (const input of [
      "first line\nsecond line",
      "<p>hello\nworld</p>",
      "<b>a</b>\n<b>b</b>",
      "<ul>\n\t<li>one</li>\r\n</ul>",
      "<pre><code>line1\n\tline2\f\n</code>\n</pre>",
    ]) {
      const output = sanitize(input);

      expect(output, input).toBe(input);
      expect(browserTree(output), input).toBe(browserTree(input));
    }

    expect(sanitize("<p>a\u0000b\u0001c\u000bd</p>")).toBe("<p>abcd</p>");
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
    const input = "<ul><li>one<li>two<ul><li>inner<li>next</ul><li>three</ul>";
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
