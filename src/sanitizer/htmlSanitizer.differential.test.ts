import { describe, it, expect } from "vitest";
import { sanitize } from "./htmlSanitizer.js";
import { DEFAULT_OPTIONS } from "./config.js";
import createDOMPurify from "dompurify";
import sanitizeHtml from "sanitize-html";
import { JSDOM } from "jsdom";

const { window } = new JSDOM("");
const DOMPurify = createDOMPurify(window as unknown as typeof globalThis);

const allowedTags = [...DEFAULT_OPTIONS.allowedTags];

const allowedAttributeMap = DEFAULT_OPTIONS.allowedAttributes;
const globalAttributes = [...(allowedAttributeMap["*"] ?? [])];

const domPurifyAllowedAttrs = Array.from(
  new Set(
    Object.entries(allowedAttributeMap).flatMap(([tag, attrs]) =>
      tag === "*" ? attrs : attrs
    )
  )
);

const forbidTags = [
  "script",
  "style",
  "iframe",
  "template",
  "svg",
  "math",
  "form",
  "object",
  "embed",
  "link",
  "meta",
];

const defaultAllowedSchemes = ["http", "https", "mailto", "tel", "ftp", "sms"];

function sanitizeWithDOMPurify(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: allowedTags,
    ALLOWED_ATTR: domPurifyAllowedAttrs,
    FORBID_TAGS: forbidTags,
    FORBID_ATTR: ["style"],
    ALLOW_DATA_ATTR: false,
  });
}

function sanitizeWithSanitizeHtml(html: string): string {
  const allowedAttributes = Object.fromEntries(
    Object.entries(allowedAttributeMap).map(([tag, attrs]) => [tag, [...attrs]])
  );
  allowedAttributes["*"] = globalAttributes;

  return sanitizeHtml(html, {
    allowedTags,
    allowedAttributes,
    allowedSchemes: defaultAllowedSchemes,
    allowedSchemesByTag: {
      a: defaultAllowedSchemes,
      img: ["http", "https", "ftp"],
    },
    allowProtocolRelative: false,
    enforceHtmlBoundary: true,
  });
}

function canonicalize(html: string): string {
  const dom = new JSDOM(`<body>${html}</body>`);
  return dom.window.document.body.innerHTML;
}

const benignCases = [
  {
    name: "simple paragraph",
    html: "<p>Hello world</p>",
  },
  {
    name: "nested strong text",
    html: "<p>Hello <strong>world</strong></p>",
  },
  {
    name: "link with safe attributes",
    html: '<a href="https://example.com" rel="noopener" target="_blank" class="btn">Visit</a>',
  },
  {
    name: "image with metadata",
    html: '<img src="https://example.com/x.png" alt="Example" width="100" height="50" class="img" />',
  },
  {
    name: "table structure",
    html: '<table class="layout"><tr><td id="cell">content</td></tr></table>',
  },
  {
    name: "code block inside div",
    html: '<div id="note" class="alert"><code>const x = 1;</code></div>',
  },
];

describe("htmlSanitizer differential behavior", () => {
  for (const testCase of benignCases) {
    it(`matches reference sanitizers for ${testCase.name}`, () => {
      const unsaneResult = canonicalize(sanitize(testCase.html));
      const domPurifyResult = canonicalize(
        sanitizeWithDOMPurify(testCase.html)
      );
      const sanitizeHtmlResult = canonicalize(
        sanitizeWithSanitizeHtml(testCase.html)
      );

      expect([domPurifyResult, sanitizeHtmlResult]).toContain(unsaneResult);
    });
  }
});
