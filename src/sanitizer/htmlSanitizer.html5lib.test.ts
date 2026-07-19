import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import corpus from "../../test/corpus/html5lib-applicable.json";
import { SanitizerOptions } from "../types.js";
import { sanitize } from "./htmlSanitizer.js";

type Token = [type: string, ...fields: unknown[]];

const voidElements = new Set(
  "area base br col embed hr img input link meta param source track wbr".split(
    " ",
  ),
);

function escapeText(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;");
}

function escapeAttribute(value: string): string {
  return escapeText(value).replace(/"/g, "&quot;");
}

function policyFor(tokens: Token[]): SanitizerOptions {
  const tags = new Set<string>();
  const attributes = new Set<string>();

  for (const [type, name, values] of tokens) {
    if (type === "StartTag" || type === "EndTag") {
      tags.add(String(name));
    }
    if (type === "StartTag" && values) {
      for (const attribute of Object.keys(values as Record<string, string>)) {
        attributes.add(attribute);
      }
    }
  }

  return {
    allowedTags: [...tags],
    allowedAttributes: { "*": [...attributes] },
  };
}

function serializeReferenceTokens(tokens: Token[]): string {
  let html = "";

  for (const [type, name, values, selfClosing] of tokens) {
    if (type === "Character") {
      html += escapeText(String(name));
    } else if (type === "StartTag") {
      const attributes = Object.entries(
        (values as Record<string, string>) ?? {},
      )
        .map(
          ([attribute, value]) =>
            ` ${attribute}="${escapeAttribute(value)}"`,
        )
        .join("");
      const tagName = String(name);
      html += `<${tagName}${attributes}>`;
      if (selfClosing && !voidElements.has(tagName)) html += `</${tagName}>`;
    } else if (type === "EndTag") {
      html += `</${String(name)}>`;
    }
  }

  return html;
}

function browserFragment(html: string): string {
  return new JSDOM(`<body>${html}</body>`).window.document.body.innerHTML;
}

describe("html5lib tokenizer conformance subset", () => {
  for (const testCase of corpus.cases) {
    it(`${testCase.file}: ${testCase.description}`, () => {
      const tokens = testCase.output as Token[];
      const expected = browserFragment(serializeReferenceTokens(tokens));
      const actual = browserFragment(sanitize(testCase.input, policyFor(tokens)));

      expect(actual).toBe(expected);
    });
  }
});
