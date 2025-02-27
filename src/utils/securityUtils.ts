/**
 * Security utilities for HTML sanitization
 */

// List of dangerous protocols that should be removed
export const DANGEROUS_PROTOCOLS = [
  "javascript:",
  "data:",
  "vbscript:",
  "mhtml:",
  "file:",
  "blob:",
  "filesystem:"
];

// List of dangerous content patterns
export const DANGEROUS_CONTENT = [
  // Code execution
  "javascript",
  "eval(",
  "new Function",
  "setTimeout(",
  "setInterval(",
  
  // XSS common vectors
  "alert(",
  "confirm(",
  "prompt(",
  "document.",
  "window.",
  
  // Event handlers
  "onerror=",
  "onclick=",
  "onload=",
  "onmouseover="
];

/**
 * Check if a value contains dangerous content like script, JavaScript,
 * event handlers or other potentially harmful patterns
 * 
 * @param value The string to check
 * @returns True if the value contains dangerous content
 */
export function containsDangerousContent(value: string): boolean {
  if (!value) return false;
  
  // Normalize for comparison
  const normalized = value.toLowerCase().replace(/\s+/g, "");
  
  // Check for dangerous protocols
  for (const protocol of DANGEROUS_PROTOCOLS) {
    if (normalized.includes(protocol)) {
      return true;
    }
  }
  
  // Check for dangerous content patterns
  for (const pattern of DANGEROUS_CONTENT) {
    if (normalized.includes(pattern.toLowerCase())) {
      return true;
    }
  }
  
  // Check for control characters and Unicode obfuscation
  if (
    normalized.includes("\\u0000") ||
    normalized.includes("\u0000") || // Actual null character
    // Control characters
    normalized.split("").some(char => {
      const code = char.charCodeAt(0);
      return code <= 0x1F || (code >= 0x7F && code <= 0x9F);
    }) ||
    // Check for zero-width characters used for obfuscation
    normalized.includes(String.fromCodePoint(0x200C)) || // Zero-width non-joiner
    normalized.includes(String.fromCodePoint(0x200D)) || // Zero-width joiner
    normalized.includes(String.fromCodePoint(0xFEFF))    // Zero-width no-break space
  ) {
    return true;
  }
  
  return false;
}

/**
 * Sanitize text content by removing or encoding potentially dangerous patterns
 * 
 * @param text Text to sanitize
 * @param encode Function to encode unsafe content
 * @returns Sanitized text
 */
export function sanitizeTextContent(text: string, encode: (s: string) => string): string {
  if (!text) return '';
  
  // Simple regex pattern for common dangerous strings
  const dangerousPattern = /javascript|script|alert|eval|onerror|onclick|on\w+\s*=|\(\s*\)|function/gi;
  
  return text.replace(dangerousPattern, match => encode(match));
}

export default {
  DANGEROUS_PROTOCOLS,
  DANGEROUS_CONTENT,
  containsDangerousContent,
  sanitizeTextContent
};