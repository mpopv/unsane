/**
 * HTML Entity handling utilities
 */

// Simple HTML entity maps - could be expanded for full coverage
const NAMED_TO_CHAR: Record<string, string> = {
  quot: '"',
  amp: "&",
  lt: "<",
  gt: ">",
  apos: "'",
};

const CHAR_TO_NAMED: Record<string, string> = {
  '"': "quot",
  "&": "amp",
  "<": "lt",
  ">": "gt",
  "'": "apos",
};

// Additional dangerous protocols that should be sanitized
export const DANGEROUS_PROTOCOLS = [
  "javascript:",
  "data:",
  "vbscript:",
  "mhtml:",
  "file:",
  "blob:",
  "filesystem:",
];

/**
 * Convert a code point to a string, handling surrogate pairs
 */
function codePointToString(codePoint: number): string {
  if (codePoint < 0 || codePoint > 0x10ffff) return "\uFFFD";
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) return "\uFFFD";

  if (codePoint > 0xffff) {
    codePoint -= 0x10000;
    return String.fromCharCode(
      0xd800 + (codePoint >> 10),
      0xdc00 + (codePoint & 0x3ff)
    );
  }

  return String.fromCharCode(codePoint);
}

/**
 * Decode a numeric HTML entity reference
 */
function decodeNumericReference(body: string): string {
  let codePoint = 0;

  if (body[0] === "x" || body[0] === "X") {
    // Hex format
    const hex = body.slice(1);
    if (!/^[0-9A-Fa-f]+$/.test(hex)) return "&#" + body + ";";
    codePoint = parseInt(hex, 16);
  } else {
    // Decimal format
    if (!/^[0-9]+$/.test(body)) return "&#" + body + ";";
    codePoint = parseInt(body, 10);
  }

  return codePointToString(codePoint);
}

/**
 * Decode a single HTML entity
 */
function decodeEntity(entity: string): string {
  let body = entity.slice(1);
  const hasSemicolon = body.endsWith(";");

  if (hasSemicolon) body = body.slice(0, -1);

  if (body[0] === "#") {
    const result = decodeNumericReference(body.slice(1));
    if (result.startsWith("&#")) return entity;
    return result;
  }

  const char = NAMED_TO_CHAR[body];
  return char && hasSemicolon ? char : entity;
}

/**
 * Decode all HTML entities in a string
 */
export function decode(text: string): string {
  return text.replace(/&(#?[0-9A-Za-z]+);?/g, (match) => decodeEntity(match));
}

/**
 * Escape special characters to prevent XSS
 */
export function escape(text: string): string {
  if (!text) return "";

  const asString = String(text);

  // Standard case - use consistent encoding
  return asString.replace(/["'&<>`]/g, (char) => {
    switch (char) {
      case '"':
        return "&quot;";
      case "'":
        return "&#x27;";
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case "`":
        return "&#x60;";
      default:
        return char;
    }
  });
}

/**
 * Create numeric HTML entity reference
 */
function numericReference(codePoint: number, decimal: boolean): string {
  return decimal
    ? "&#" + codePoint + ";"
    : "&#x" + codePoint.toString(16).toUpperCase() + ";";
}

/**
 * Options for entity encoding
 */
export interface EncodeOptions {
  useNamedReferences?: boolean;
  encodeEverything?: boolean;
  decimal?: boolean;
}

/**
 * Encode characters to HTML entities
 */
export function encode(text: string, options: EncodeOptions = {}): string {
  const {
    useNamedReferences = false,
    encodeEverything = false,
    decimal = false,
  } = options;

  const result = [];

  for (const char of text) {
    const codePoint = char.codePointAt(0) || char.charCodeAt(0);

    if (CHAR_TO_NAMED[char]) {
      if (useNamedReferences) {
        result.push("&", CHAR_TO_NAMED[char], ";");
      } else {
        result.push(numericReference(codePoint, decimal));
      }
    } else {
      if (!encodeEverything && codePoint >= 0x20 && codePoint < 0x7f) {
        result.push(char);
        continue;
      }
      result.push(numericReference(codePoint, decimal));
    }
  }

  return result.join("");
}

/**
 * Check if a URL might be dangerous (contains script or dangerous protocol)
 * @param url URL to check
 * @returns True if URL is potentially dangerous
 */
export function isUnsafeUrl(url: string): boolean {
  if (!url) return false;
  
  // Sanitize and normalize for comparison
  const normalized = url.trim().toLowerCase().replace(/\s+/g, "");
  
  // Check for dangerous protocols
  for (const protocol of DANGEROUS_PROTOCOLS) {
    if (normalized.startsWith(protocol)) {
      return true;
    }
  }
  
  // Check for Unicode escapes and control characters
  if (
    normalized.includes("\\u0000") ||
    normalized.includes("\0") ||
    normalized.split("").some((char) => char.charCodeAt(0) <= 0x1f) ||
    // Check for obfuscation patterns
    normalized.includes("\\u00") ||  // Unicode escapes
    normalized.includes("&#") ||     // HTML entity obfuscation
    normalized.includes("%") ||      // URL encoding that might be hiding something
    normalized.includes(String.fromCodePoint(0x200c)) || // Zero-width non-joiner
    normalized.includes(String.fromCodePoint(0x200d))    // Zero-width joiner
  ) {
    return true;
  }
  
  // Check for script-like content
  if (
    normalized.includes("javascript") ||
    normalized.includes("script") ||
    normalized.includes("eval(") ||
    normalized.includes("alert(") ||
    normalized.includes("function(") ||
    (normalized.includes("on") && normalized.includes("="))
  ) {
    return true;
  }
  
  return false;
}

export default {
  decode,
  encode,
  escape,
  isUnsafeUrl,
  DANGEROUS_PROTOCOLS
};