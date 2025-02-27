/**
 * htmlEntities.ts
 * A local replication of the core functionalities of the `he` library:
 *   1. decode(...): Decode named (&amp;), decimal (&#123;), hex (&#x7B;) references
 *   2. encode(...): Encode non-ASCII / special chars to numeric or named refs
 *   3. escape(...): Minimal escaping of critical characters (&, <, >, ", ', `)
 *
 * Extend or customize as needed for full HTML5 coverage.
 */

// Named references you want to handle. This small subset can be replaced
// or expanded with the entire data from `he` if you desire full coverage.
const NAMED_TO_CHAR: Record<string, string> = {
  quot: '"',
  amp: "&",
  lt: "<",
  gt: ">",
  apos: "'",
  // Add as many as you need. For full coverage, embed from he's decode-map.
};

// We can also do the reverse mapping if you want to use named refs in `encode`.
const CHAR_TO_NAMED: Record<string, string> = {
  '"': "quot",
  "&": "amp",
  "<": "lt",
  ">": "gt",
  "'": "apos",
};

/**
 * Convert a single code point into a string (handling surrogate pairs).
 * Out-of-range code points (e.g. > 0x10FFFF) or lone surrogates will return U+FFFD.
 */
function codePointToString(codePoint: number): string {
  // Basic validity checks
  if (codePoint < 0 || codePoint > 0x10ffff) {
    return "\uFFFD";
  }
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
    // Surrogates are invalid in HTML references
    return "\uFFFD";
  }
  // Convert if in astral plane
  if (codePoint > 0xffff) {
    codePoint -= 0x10000;
    const high = 0xd800 + (codePoint >> 10);
    const low = 0xdc00 + (codePoint & 0x3ff);
    return String.fromCharCode(high, low);
  }
  return String.fromCharCode(codePoint);
}

/**
 * Decode a numeric HTML entity of the form:
 *   - &#NNN;        (decimal)
 *   - &#xHH; or &#XHH; (hex)
 * Returns the decoded string or replacement char on invalid input.
 */
function decodeNumericReference(
  entityBody: string // either "123" or "x1A3" / "X1A3" (hex)
): string {
  // If strictSemicolon is true, you might want to throw or parseError, but
  // here we'll just decode best-effort.
  let codePoint = 0;
  if (entityBody[0] === "x" || entityBody[0] === "X") {
    // Hex
    const hex = entityBody.slice(1);
    if (!hex.match(/^[0-9A-Fa-f]+$/)) {
      return "\uFFFD";
    }
    codePoint = parseInt(hex, 16);
  } else {
    // Decimal
    if (!entityBody.match(/^[0-9]+$/)) {
      return "\uFFFD";
    }
    codePoint = parseInt(entityBody, 10);
  }
  return codePointToString(codePoint);
}

/**
 * Decode an HTML entity. Supports:
 *   - &amp; &lt; &gt; &quot; etc. (from NAMED_TO_CHAR)
 *   - numeric decimal &#123; / numeric hex &#x7B;
 * gracefully falls back to leaving `&...` alone if invalid or incomplete.
 *
 * This is the core of `he.decode` logic. For a single chunk of text, you might
 * want to parse and replace multiple entities. decodeHtml() below does that.
 */
function decodeEntity(entity: string): string {
  // Possible forms:
  //   &name;
  //   &#NNN;
  //   &#xNNN;
  //
  // We skip "strict mode" complexities for brevity.
  // If it's just `&` or `&someInvalid` we may fallback to literal text.

  // Remove leading "&" and trailing ";" if present
  let body = entity.slice(1);
  const hasSemi = body.endsWith(";");
  if (hasSemi) {
    body = body.slice(0, -1);
  }
  // Check if numeric
  if (body[0] === "#") {
    return decodeNumericReference(body.slice(1));
  }
  // Otherwise a named entity
  const mapped = NAMED_TO_CHAR[body];
  if (mapped && hasSemi) {
    return mapped;
  }
  // Return original if unknown or missing semicolon for named entities
  return entity;
}

/**
 * Decodes all HTML entities (named or numeric) found in `text`.
 * Similar to `he.decode(text, options?)`.
 */
export function decode(text: string): string {
  // This regex attempts to capture any `&...;` chunk.
  return text.replace(/&(#?[0-9A-Za-z]+);?/g, (match) => decodeEntity(match));
}

/**
 * Minimal "escape" that replaces only critical characters in HTML contexts.
 * Equivalent to `he.escape`.
 */
export function escape(text: string): string {
  return text.replace(/["'&<>`]/g, (ch) => {
    // For minimal coverage we can do a direct map:
    switch (ch) {
      case '"':
        return "&quot;";
      case "'":
        return "&apos;";
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case "`":
        return "&#x60;";
      default:
        return ch;
    }
  });
}

/**
 * Encode a string into HTML entities.
 * Options:
 *   - useNamedReferences: if true, use e.g. &quot; for "
 *   - encodeEverything: if true, transform every code point outside basic ASCII
 *   - decimal: if true, numeric references are decimal (&#65;), else hex (&#x41;)
 *
 * This is a partial replication of `he.encode(text, { ... })`.
 */
interface EncodeOptions {
  useNamedReferences?: boolean;
  encodeEverything?: boolean;
  decimal?: boolean;
}

export function encode(
  text: string,
  {
    useNamedReferences = false,
    encodeEverything = false,
    decimal = false,
  }: EncodeOptions = {}
): string {
  // If not encoding everything, we only encode & < > " ' ` by default—like a minimal approach.
  // If encodeEverything=true, we transform *all* non-ASCII codepoints to numeric or named if available.

  const out: string[] = [];

  for (const char of text) {
    const code = char.codePointAt(0) ?? char.charCodeAt(0);

    // 1) If this char is among the "core 6" (amp, lt, gt, quot, apos, `):
    if (CHAR_TO_NAMED[char]) {
      // Use named if user requests
      if (useNamedReferences) {
        out.push("&", CHAR_TO_NAMED[char], ";");
      } else {
        // Otherwise numeric
        out.push(numRef(code, decimal));
      }
      continue;
    }

    // 2) Possibly skip normal ASCII if not `encodeEverything`.
    if (!encodeEverything) {
      // If it's a safe ASCII char, just push it.
      if (code >= 0x20 && code < 0x7f) {
        out.push(char);
        continue;
      }
    }

    // 3) If useNamedReferences and we have a known named entity, use it
    // (We only have a small subset above, so for broad coverage you'd store
    //  a big map from all codepoints to named references.)
    // If the user wants that, they'd do something like:
    //   const named = CODEPOINT_TO_NAMED[code];
    //   if (named) { out.push('&', named, ';'); continue; }

    // 4) Fall back to numeric references
    out.push(numRef(code, decimal));
  }

  return out.join("");
}

function numRef(code: number, decimal: boolean): string {
  return decimal ? `&#${code};` : `&#x${code.toString(16).toUpperCase()};`;
}

// Default-export an object for a single import
export default {
  decode,
  encode,
  escape,
};
