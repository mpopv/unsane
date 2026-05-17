import { describe, it, expect } from "vitest";
import { sanitize } from "./htmlSanitizer.js";

const unsafeTagPatterns = [
  /<script\b/i,
  /<style\b/i,
  /<iframe\b/i,
  /<object\b/i,
  /<svg\b/i,
  /<math\b/i,
  /\son[a-z]+\s*=/i,
  /\sstyle\s*=/i,
  /\s(?:href|src|action|formaction|xlink:href)=["']?\s*(?:javascript|data|vbscript|file|blob|mhtml|filesystem):/i,
];

const voidTags = new Set(["br", "hr", "img"]);
const nonVoidTags = [
  "a",
  "blockquote",
  "code",
  "div",
  "em",
  "h1",
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

function createPrng(seed: number): () => number {
  let state = seed >>> 0;

  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function pick<T>(random: () => number, values: T[]): T {
  return values[Math.floor(random() * values.length)];
}

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

function generatedPayloads(count: number): string[] {
  const random = createPrng(0x5eed);
  const tagNames = [
    ...nonVoidTags,
    "script",
    "style",
    "iframe",
    "svg",
    "math",
    "object",
    "unknown",
  ];
  const attrNames = [
    "href",
    "src",
    "class",
    "id",
    "style",
    "onclick",
    "onerror",
    "xlink:href",
    "data-test",
  ];
  const values = [
    "safe",
    "https://example.com/x",
    "javascript:alert(1)",
    "java\u0000script:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "hello &lt;script&gt;",
    "unterminated",
    "",
  ];
  const textParts = [
    "plain text",
    "1 < 2 & 3",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "\u0000control\u001Fchars",
    "<<broken",
    "javascript alert script as text",
  ];
  const quoteStyles = ['"', "'", ""];
  const payloads: string[] = [];

  for (let i = 0; i < count; i++) {
    const tagName = pick(random, tagNames);
    const attrs = Array.from({ length: 1 + Math.floor(random() * 4) }, () => {
      const name = pick(random, attrNames);
      const value = pick(random, values);
      const quote = pick(random, quoteStyles);

      if (!value) return name;
      if (!quote) return `${name}=${value}`;

      return `${name}=${quote}${value}${quote}`;
    }).join(" ");
    const text = pick(random, textParts);
    const close = random() > 0.35 ? `</${pick(random, tagNames)}>` : "";
    const prefix = random() > 0.85 ? "<" : "";
    const suffix = random() > 0.8 ? ">" : "";

    payloads.push(`${prefix}<${tagName} ${attrs}>${text}${close}${suffix}`);
  }

  return payloads;
}

describe("htmlSanitizer generated corpus", () => {
  it("never throws and preserves sanitizer output invariants", () => {
    for (const input of generatedPayloads(300)) {
      let output = "";

      expect(() => {
        output = sanitize(input);
      }).not.toThrow();

      expectSafeTagTokens(output, input);
      expect(balancedAllowedTags(output), input).toBe(true);
    }
  });
});
