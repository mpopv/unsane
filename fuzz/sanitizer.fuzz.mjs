import { JSDOM } from "jsdom";
import { createSanitizer } from "../dist/index.js";
import { isSafeUrlAttributeValue } from "../dist/utils/securityUtils.js";

const tags = [
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
];
const attributes = [
  "aria-label",
  "class",
  "data-test",
  "href",
  "id",
  "onclick",
  "rel",
  "src",
  "srcdoc",
  "srcset",
  "style",
  "target",
  "title",
];
const forbiddenTagPattern = /^(?:base|embed|iframe|link|math|meta|object|script|style|svg)$/i;
const forbiddenAttributePattern =
  /^(?:on|style$|action$|formaction$|xlink:href$|srcdoc$|srcset$|imagesrcset$|ping$|is$)/i;
const unsafeProtocolPattern =
  /^\s*(?:javascript|data|vbscript|file|blob|mhtml|filesystem):/i;
const body = new JSDOM("<body></body>").window.document.body;

function select(values, data, offset) {
  const selected = [];
  for (let index = 0; index < values.length; index++) {
    if ((data[(offset + index) % Math.max(data.length, 1)] ?? 0) & 1) {
      selected.push(values[index]);
    }
  }
  return selected;
}

function assertSafeTokens(output) {
  for (const token of output.match(/<[^>]*>/g) ?? []) {
    if (/<\/?(?:script|style|iframe|object|embed|svg|math|base|link|meta)\b/i.test(token)) {
      throw new Error(`Forbidden element token: ${token}`);
    }
    if (/\s(?:on[a-z]+|style|srcdoc|srcset|imagesrcset|ping|is)=/i.test(token)) {
      throw new Error(`Forbidden attribute token: ${token}`);
    }
  }
}

function assertSafeDom(output) {
  body.innerHTML = output;

  for (const element of body.querySelectorAll("*")) {
    if (forbiddenTagPattern.test(element.localName)) {
      throw new Error(`Forbidden DOM element: ${element.localName}`);
    }

    for (const attribute of element.attributes) {
      if (forbiddenAttributePattern.test(attribute.name)) {
        throw new Error(`Forbidden DOM attribute: ${attribute.name}`);
      }
      if (
        /^(?:href|src|cite|poster)$/i.test(attribute.name) &&
        unsafeProtocolPattern.test(attribute.value)
      ) {
        throw new Error(`Unsafe DOM URL: ${attribute.value}`);
      }
    }
  }
}

export function fuzz(data) {
  const input = data.toString("utf8");
  const options = {
    allowedTags: select(tags, data, 0),
    allowedAttributes: { "*": select(attributes, data, 7) },
    maxInputLength: 65_536,
  };
  const sanitize = createSanitizer(options);
  const output = sanitize(input);

  if (sanitize(input) !== output) throw new Error("Non-deterministic output");
  if (sanitize(output) !== output) throw new Error("Non-canonical output");
  if (output.length > input.length * 8 + 256) {
    throw new Error(`Output expansion ${input.length} -> ${output.length}`);
  }
  if (
    isSafeUrlAttributeValue(input) !== isSafeUrlAttributeValue(input)
  ) {
    throw new Error("Non-deterministic URL classification");
  }

  assertSafeTokens(output);

  // Sample the slower DOM oracle while keeping the coverage-guided loop fast.
  if (((data[0] ?? 0) ^ (data[data.length - 1] ?? 0)) % 32 === 0) {
    assertSafeDom(output);
  }
}
