import { describe, it, expect } from "vitest";
import { sanitize } from "./htmlSanitizer.js";

interface VectorCase {
  name: string;
  html: string;
  expected?: string;
  forbidden?: RegExp[];
}

const vectors: VectorCase[] = [
  {
    name: "IMG javascript protocol (double quoted)",
    html: '<IMG SRC="javascript:alert(\'XSS\');">',
    expected: "<img />",
  },
  {
    name: "IMG javascript protocol (unquoted)",
    html: "<IMG SRC=javascript:alert('XSS')>",
    expected: "<img />",
  },
  {
    name: "IMG javascript protocol (mixed case)",
    html: "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    expected: "<img />",
  },
  {
    name: "IMG javascript protocol with whitespace",
    html: "<IMG SRC=\" javascript:alert('XSS')\">",
    expected: "<img />",
  },
  {
    name: "IMG javascript protocol with control char",
    html: "<IMG SRC=\"jav\u0000ascript:alert('XSS')\">",
    expected: "<img />",
  },
  {
    name: "IMG javascript protocol with entity encoding",
    html: "<IMG SRC=\"javascript:alert(&#34;XSS&#34;)\">",
    expected: "<img />",
  },
  {
    name: "Anchor javascript protocol",
    html: '<a href="javascript:alert(1)">payload</a>',
    expected: "<a>payload</a>",
  },
  {
    name: "Anchor javascript protocol obfuscated",
    html: '<a href="j&#97;vascript:alert(1)">payload</a>',
    expected: "<a>payload</a>",
  },
  {
    name: "CSS background-image javascript URL",
    html: '<div style="background-image: url(javascript:alert(1))">payload</div>',
    expected: "<div>payload</div>",
  },
  {
    name: "SVG onload attribute",
    html: '<svg><g onload="alert(1)"></g></svg>',
    forbidden: [/svg/i, /onload/i, /alert/i],
  },
  {
    name: "SVG animate javascript href",
    html: '<svg><animate xlink:href="#x" values="javascript:alert(1)"></animate></svg>',
    forbidden: [/svg/i, /animate/, /javascript/i, /alert/i],
  },
  {
    name: "Commented script tag payload",
    html: "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    forbidden: [/script/i, /alert/i],
  },
  {
    name: "Malformed script tag with entity encoding",
    html: "&lt;script&gt;alert(1)&lt;/script&gt;",
    expected: "&lt;script&gt;alert(1)&lt;/script&gt;",
  },
];

describe("htmlSanitizer OWASP vectors", () => {
  for (const vector of vectors) {
    it(`neutralizes ${vector.name}`, () => {
      const result = sanitize(vector.html);

      if (typeof vector.expected !== "undefined") {
        expect(result).toBe(vector.expected);
      }

      if (vector.forbidden) {
        for (const pattern of vector.forbidden) {
          expect(result).not.toMatch(pattern);
        }
      }
    });
  }
});
