import { describe, it, expect } from "vitest";
import { sanitize } from "./htmlSanitizer.js";

interface SecurityCase {
  name: string;
  html: string;
  required?: RegExp[];
}

const executableOutputPatterns = [
  /<script\b/i,
  /<style\b/i,
  /<iframe\b/i,
  /<svg\b/i,
  /<math\b/i,
  /\son[a-z]+\s*=/i,
  /\sstyle\s*=/i,
  /\s(?:href|src|action|formaction|xlink:href)=["']?\s*(?:javascript|data|vbscript|file|blob|mhtml|filesystem):/i,
  /alert\s*\(/i,
  /confirm\s*\(/i,
  /prompt\s*\(/i,
  /document\./i,
  /window\./i,
];

const corpus: SecurityCase[] = [
  {
    name: "image event handler",
    html: "<img src=x onerror=alert(1)>",
  },
  {
    name: "javascript link",
    html: '<a href="javascript:confirm(1)">link</a>',
    required: [/^<a>link<\/a>$/],
  },
  {
    name: "data URL document",
    html: '<a href="data:text/html,<script>alert(1)</script>">link</a>',
    required: [/^<a>link<\/a>$/],
  },
  {
    name: "svg namespace payload",
    html: '<svg><a xlink:href="javascript:alert(1)">x</a></svg>',
  },
  {
    name: "math namespace payload",
    html: '<math><mi xlink:href="data:x">x</mi></math>',
  },
  {
    name: "inline style and event handler",
    html: '<div style="background:url(javascript:alert(1))" onclick="alert(1)">x</div>',
    required: [/^<div>x<\/div>$/],
  },
  {
    name: "object fallback",
    html: '<object data="javascript:alert(1)">x</object>',
  },
  {
    name: "vbscript link",
    html: '<a href="vbscript:msgbox(1)">link</a>',
    required: [/^<a>link<\/a>$/],
  },
  {
    name: "safe link with dangerous extra attribute",
    html: '<a href="https://example.com" onclick="alert(1)" rel="nofollow">link</a>',
    required: [/href="https:\/\/example\.com"/, /rel="nofollow"/],
  },
];

describe("security corpus", () => {
  for (const testCase of corpus) {
    it(`neutralizes ${testCase.name}`, () => {
      const result = sanitize(testCase.html);

      for (const pattern of executableOutputPatterns) {
        expect(result).not.toMatch(pattern);
      }

      for (const pattern of testCase.required ?? []) {
        expect(result).toMatch(pattern);
      }
    });
  }

  it("preserves suspicious words when they are inert text", () => {
    expect(
      sanitize("<p>javascript alert script onclick= are text here</p>")
    ).toBe("<p>javascript alert script onclick= are text here</p>");
  });
});
