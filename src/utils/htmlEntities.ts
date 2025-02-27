/**
 * HTML Entity handling utilities - simplified and optimized version
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
 * Decode all HTML entities in a string
 */
export function decode(text: string): string {
  if (!text) return "";
  
  return text.replace(/&(#?[0-9A-Za-z]+);?/g, (match, entity) => {
    // Return the match as-is if it doesn't end with a semicolon
    if (!match.endsWith(';')) {
      return match;
    }
    
    // Remove trailing semicolon
    entity = entity.replace(/;$/, '');
    
    if (entity[0] === "#") {
      // Numeric entity
      if (entity.length < 2) return match;
      
      // Handle hex or decimal
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

/**
 * Escape special characters to prevent XSS
 */
export function escape(text: string): string {
  if (!text) return "";
  
  return String(text).replace(/["'&<>`]/g, char => {
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
 * Options for entity encoding
 */
export interface EncodeOptions {
  useNamedReferences?: boolean;
  decimal?: boolean;
}

/**
 * Options for entity encoding
 */
export interface EncodeOptions {
  useNamedReferences?: boolean;
  decimal?: boolean;
  encodeEverything?: boolean;
}

/**
 * Encode characters to HTML entities
 */
export function encode(text: string, options: EncodeOptions = {}): string {
  if (!text) return "";
  
  const { 
    useNamedReferences = false, 
    decimal = false,
    encodeEverything = false 
  } = options;
  
  // If we need to encode everything, use a different pattern
  const pattern = encodeEverything ? /./g : /["&<>']/g;
  
  return String(text).replace(pattern, char => {
    // For normal chars that aren't special, only encode if encodeEverything is true
    if (!encodeEverything && !(/["&<>']/.test(char))) {
      return char;
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

export default {
  decode,
  encode,
  escape
};