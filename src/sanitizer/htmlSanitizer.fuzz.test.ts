import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import * as fc from "fast-check";
import regressions from "../../test/corpus/sanitizer-regressions.json";
import { SanitizerOptions } from "../types.js";
import { sanitize } from "./htmlSanitizer.js";

const unsafeTagPatterns = [
  /<script\b/i,
  /<style\b/i,
  /<iframe\b/i,
  /<object\b/i,
  /<svg\b/i,
  /<math\b/i,
  /\s(?:href|src|action|formaction|xlink:href)=["']?\s*(?:javascript|data|vbscript|file|blob|mhtml|filesystem):/i,
];

const voidTags = new Set(["br", "hr", "img"]);
const safeTags = [
  "a",
  "blockquote",
  "code",
  "div",
  "em",
  "h1",
  "img",
  "li",
  "ol",
  "p",
  "pre",
  "span",
  "strong",
  "table",
  "td",
  "th",
  "tr",
  "ul",
] as const;
const tagNames = [
  ...safeTags,
  "script",
  "script-x",
  "style",
  "iframe",
  "object",
  "embed",
  "template",
  "textarea",
  "title",
  "noscript",
  "svg",
  "math",
  "unknown",
] as const;
const attributeNames = [
  "href",
  "src",
  "class",
  "id",
  "title",
  "target",
  "rel",
  "style",
  "onclick",
  "onerror",
  "formaction",
  "xlink:href",
  "data-test",
  "aria-label",
] as const;
const safeAttributeNames = [
  "href",
  "src",
  "class",
  "id",
  "title",
  "target",
  "rel",
  "data-test",
  "aria-label",
  "alt",
  "width",
  "height",
] as const;
const attributeValues = [
  "",
  "safe",
  "https://example.com/x",
  "/relative/path",
  "#fragment",
  "javascript:globalThis.__unsaneExecuted=true",
  "java\u0000script:alert(1)",
  "java&#x0A;script:alert(1)",
  "data:text/html,<script>alert(1)</script>",
  "vbscript:msgbox(1)",
  "hello &lt;script&gt;",
  "&amp;amp;",
  "\"quoted\"",
  "'single'",
  "unterminated",
] as const;
const textTokens = [
  "",
  "plain text",
  "1 < 2 & 3",
  "&lt;script&gt;alert(1)&lt;/script&gt;",
  "\u0000control\u001Fchars",
  "<<broken",
  "<!--comment-->",
  "<![CDATA[foreign]]>",
  "</",
  "/>",
  "=",
  '"',
  "'",
  "javascript alert script as text",
] as const;

const tagNameArbitrary = fc.constantFrom(...tagNames);
const attributeNameArbitrary = fc.constantFrom(...attributeNames);
const attributeValueArbitrary = fc.constantFrom(...attributeValues);
const quoteArbitrary = fc.constantFrom('"', "'", "");
const whitespaceArbitrary = fc.constantFrom("", " ", "\t", "\n", "\r\n");

const attributeArbitrary = fc
  .tuple(
    attributeNameArbitrary,
    attributeValueArbitrary,
    quoteArbitrary,
    whitespaceArbitrary,
    fc.boolean(),
  )
  .map(([name, value, quote, whitespace, booleanAttribute]) =>
    booleanAttribute
      ? `${whitespace}${name}`
      : `${whitespace}${name}${whitespace}=${whitespace}${quote}${value}${quote}`,
  );

const structuredElementArbitrary = fc
  .record({
    attributes: fc.array(attributeArbitrary, { maxLength: 6 }),
    body: fc.constantFrom(...textTokens),
    closeStyle: fc.constantFrom("matching", "wrong", "missing", "self"),
    tagName: tagNameArbitrary,
  })
  .map(({ attributes, body, closeStyle, tagName }) => {
    const open = `<${tagName}${attributes.join("")}${
      closeStyle === "self" ? "/>" : ">"
    }`;

    if (closeStyle === "self") return `${open}${body}`;
    if (closeStyle === "missing") return `${open}${body}`;

    return `${open}${body}</${
      closeStyle === "matching" ? tagName : "div"
    }>`;
  });

const rawContentArbitrary = fc
  .tuple(
    fc.constantFrom(
      "script",
      "style",
      "iframe",
      "template",
      "textarea",
      "title",
      "noscript",
      "svg",
      "math",
    ),
    fc.constantFrom(...attributeValues, ...textTokens),
    fc.boolean(),
  )
  .map(
    ([tagName, body, close]) =>
      `<${tagName}>${body}${
        close ? `</${tagName}>` : ""
      }<p>safe sibling</p>`,
  );

const tokenSoupArbitrary = fc
  .array(
    fc.constantFrom(
      ...tagNames,
      ...attributeNames,
      ...attributeValues,
      ...textTokens,
      "<",
      ">",
      "</",
      "/>",
      "<!--",
      "-->",
      "=",
      " ",
    ),
    { maxLength: 80 },
  )
  .map((tokens) => tokens.join(""));

const htmlFragmentArbitrary = fc.oneof(
  structuredElementArbitrary,
  rawContentArbitrary,
  tokenSoupArbitrary,
  fc
    .array(structuredElementArbitrary, { maxLength: 8 })
    .map((elements) => elements.join("")),
);

const safePolicyArbitrary: fc.Arbitrary<SanitizerOptions | undefined> =
  fc.oneof(
    fc.constant(undefined),
    fc
      .record({
        allowedAttributes: fc.uniqueArray(
          fc.constantFrom(...safeAttributeNames),
          { maxLength: safeAttributeNames.length },
        ),
        allowedTags: fc.uniqueArray(fc.constantFrom(...safeTags), {
          maxLength: safeTags.length,
        }),
      })
      .map(({ allowedAttributes, allowedTags }) => ({
        allowedTags,
        allowedAttributes: { "*": allowedAttributes },
      })),
  );

function createBrowserBody() {
  return new JSDOM("<body></body>").window.document.body;
}

type BrowserBody = ReturnType<typeof createBrowserBody>;

function balancedAllowedTags(html: string): boolean {
  const stack: string[] = [];
  const tagPattern = /<\/?([a-z0-9-]+)(?:\s[^>]*)?>/gi;
  let match: RegExpExecArray | null;

  while ((match = tagPattern.exec(html)) !== null) {
    const fullToken = match[0];
    const tagName = match[1].toLowerCase();

    if (voidTags.has(tagName) || fullToken.endsWith("/>")) continue;

    if (fullToken.startsWith("</")) {
      if (stack.pop() !== tagName) return false;
    } else {
      stack.push(tagName);
    }
  }

  return stack.length === 0;
}

function expectSafeTagTokens(html: string, input: string): void {
  const tagTokens = html.match(/<[^>]+>/g) ?? [];

  for (const token of tagTokens) {
    for (const pattern of unsafeTagPatterns) {
      expect(token, input).not.toMatch(pattern);
    }
  }
}

function expectSafeBrowserTree(body: BrowserBody, input: string): void {
  expect(
    body.querySelector("script, style, iframe, object, svg, math"),
    input,
  ).toBeNull();

  for (const element of body.querySelectorAll("*")) {
    for (const attribute of element.attributes) {
      expect(attribute.name, input).not.toMatch(/^on|^style$/i);

      if (/^(?:href|src|action|formaction|xlink:href)$/i.test(attribute.name)) {
        expect(attribute.value, input).not.toMatch(
          /^\s*(?:javascript|data|vbscript|file|blob|mhtml|filesystem):/i,
        );
      }
    }
  }
}

function expectSanitizerInvariants(
  input: string,
  options: SanitizerOptions | undefined,
  browserBody: BrowserBody,
): void {
  const output = sanitize(input, options);

  expect(sanitize(input, options), input).toBe(output);
  expect(output.length, input).toBeLessThanOrEqual(input.length * 8 + 256);
  expectSafeTagTokens(output, input);
  expect(balancedAllowedTags(output), input).toBe(true);

  const resanitized = sanitize(output, options);
  expect(resanitized, input).toBe(output);
  expect(resanitized.length, input).toBeLessThanOrEqual(output.length * 8 + 256);
  expectSafeTagTokens(resanitized, input);
  expect(balancedAllowedTags(resanitized), input).toBe(true);

  browserBody.innerHTML = output;
  expectSafeBrowserTree(browserBody, input);
}

describe("htmlSanitizer adversarial generation", () => {
  it("preserves semantic invariants for shrinkable parser-state inputs", () => {
    const browserBody = createBrowserBody();

    fc.assert(
      fc.property(
        htmlFragmentArbitrary,
        safePolicyArbitrary,
        (input, options) => {
          expectSanitizerInvariants(input, options, browserBody);
        },
      ),
      {
        endOnFailure: true,
        numRuns: 2_000,
        seed: 0x5eedc0de,
      },
    );
  });

  it("keeps every minimized regression in the permanent corpus safe", () => {
    const browserBody = createBrowserBody();

    for (const regression of regressions) {
      expectSanitizerInvariants(regression.input, undefined, browserBody);
    }
  });
});
