/**
 * HTML Entity handling utilities - simplified and unified version
 */

// Simple HTML entity maps - common entities only
const NAMED_TO_CHAR: Record<string, string> = {
  quot: '"',
  amp: "&",
  lt: "<",
  gt: ">",
  apos: "'",
  nbsp: "\u00A0"
};

const CHAR_TO_NAMED: Record<string, string> = {
  '"': "quot",
  "&": "amp",
  "<": "lt",
  ">": "gt",
  "'": "apos"
};

// Characters to always escape for security reasons
const ESCAPE_CHARS = /["'&<>`]/g;

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
 * Options for entity encoding
 */
export interface EncodeOptions {
  useNamedReferences?: boolean; // Use named entities like &lt; instead of &#x3C;
  decimal?: boolean;           // Use decimal (&#38;) instead of hex (&#x26;)
  encodeEverything?: boolean;  // Encode all characters, not just special ones
  escapeOnly?: boolean;        // Only escape minimal set of security-sensitive characters
}

/**
 * Unified encode/escape function for HTML entities
 * 
 * @param text Text to encode
 * @param options Encoding options
 * @returns Encoded text
 */
export function encode(text: string, options: EncodeOptions = {}): string {
  if (!text) return "";
  
  const { 
    useNamedReferences = false, 
    decimal = false,
    encodeEverything = false,
    escapeOnly = false
  } = options;
  
  // Choose pattern based on encoding needs
  let pattern: RegExp;
  
  if (escapeOnly) {
    // Minimal set for security (original "escape" function behavior)
    pattern = ESCAPE_CHARS;
  } else if (encodeEverything) {
    // Encode every character
    pattern = /./g;
  } else {
    // Default - encode security-sensitive characters
    pattern = /["&<>']/g;
  }
  
  return String(text).replace(pattern, char => {
    // Skip non-target characters (should never happen due to RegExp)
    if (!escapeOnly && !encodeEverything && !(/["&<>']/.test(char))) return char;
    
    // For escape function compatibility - use fixed output format for tests
    if (escapeOnly) {
      switch (char) {
        case '"': return "&quot;";
        case "'": return "&#x27;";
        case "&": return "&amp;";
        case "<": return "&lt;";
        case ">": return "&gt;";
        case "`": return "&#x60;";
        default: return char;
      }
    }
    
    // Use named references if requested and available
    if (useNamedReferences && CHAR_TO_NAMED[char]) {
      return `&${CHAR_TO_NAMED[char]};`;
    }
    
    // Otherwise use numeric encoding
    const codePoint = char.charCodeAt(0);
    return decimal
      ? `&#${codePoint};`
      : `&#x${codePoint.toString(16).toUpperCase()};`; // Use uppercase for hex
  });
}

/**
 * Escape special characters to prevent XSS
 * This is an alias for encode with escapeOnly option for backward compatibility
 */
export function escape(text: string): string {
  return encode(text, { escapeOnly: true });
}

/**
 * Decode all HTML entities in a string
 * Only handles properly formed HTML entities with semicolons
 */
export function decode(text: string): string {
  if (!text) return "";
  
  // Only decode entities with proper semicolons, matching HTML5 parsing rules
  return text.replace(/&(#?[0-9A-Za-z]+);/g, (match, entity) => {
    if (entity[0] === "#") {
      // Numeric entity
      if (entity.length < 2) return match;
      
      try {
        const codePoint = entity[1] === "x" || entity[1] === "X"
          ? parseInt(entity.slice(2), 16)  // Hex format
          : parseInt(entity.slice(1), 10); // Decimal format
          
        // Invalid number should return original match
        if (isNaN(codePoint)) return match;
        
        return codePointToString(codePoint);
      } catch (e) {
        return match;
      }
    }
    
    // Named entity
    return NAMED_TO_CHAR[entity] || match;
  });
}

export default {
  decode,
  encode,
  escape
};