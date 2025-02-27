/**
 * Helper functions to create a DOMPurify-compatible interface for Unsane
 */

// Simple HTML entity maps - like the ones in unsane.ts
const NAMED_TO_CHAR = {
  quot: '"',
  amp: "&",
  lt: "<",
  gt: ">",
  apos: "'",
};

const CHAR_TO_NAMED = {
  '"': "quot",
  "&": "amp",
  "<": "lt",
  ">": "gt",
  "'": "apos",
};

/**
 * Convert a code point to a string, handling surrogate pairs
 */
function codePointToString(codePoint) {
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
function decodeNumericReference(body) {
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
function decodeEntity(entity) {
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
export function decode(text) {
  return text.replace(/&(#?[0-9A-Za-z]+);?/g, match => decodeEntity(match));
}

/**
 * Escape special characters to prevent XSS
 */
export function escape(text) {
  if (!text) return '';
  
  const asString = String(text);
  
  // Standardize quote encoding (use consistent encoding for both single and double quotes)
  return asString.replace(/["'&<>`]/g, char => {
    switch (char) {
      case '"': return "&quot;";
      case "'": return "&#x27;";
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case "`": return "&#x60;";
      default: return char;
    }
  });
}

/**
 * Create numeric HTML entity reference
 */
function numericReference(codePoint, decimal) {
  return decimal 
    ? "&#" + codePoint + ";" 
    : "&#x" + codePoint.toString(16).toUpperCase() + ";";
}

/**
 * Encode characters to HTML entities
 */
export function encode(text, options = {}) {
  const { 
    useNamedReferences = false, 
    encodeEverything = false, 
    decimal = false 
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
      if (!encodeEverything && (codePoint >= 0x20 && codePoint < 0x7f)) {
        result.push(char);
        continue;
      }
      result.push(numericReference(codePoint, decimal));
    }
  }
  
  return result.join("");
}