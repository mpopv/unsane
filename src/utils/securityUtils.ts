/**
 * Security utilities for HTML sanitization
 */

// Only these protocols are allowed (allowlist approach)
export const ALLOWED_PROTOCOLS = new Set([
  "http:",
  "https:",
  "mailto:",
  "tel:",
  "ftp:",
  "sms:",
]);

// List of dangerous content patterns
export const DANGEROUS_CONTENT = [
  // Code execution
  "javascript",
  "eval(",
  "newfunction",
  "settimeout(",
  "setinterval(",

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
  "onmouseover=",
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

  // Check for control characters and Unicode obfuscation first (before normalization)
  if (
    value.includes("\\u0000") ||
    value.includes("\u0000") || // Actual null character
    // Control characters
    value.split("").some((char) => {
      const code = char.charCodeAt(0);
      return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
    }) ||
    // Check for zero-width characters used for obfuscation
    value.includes(String.fromCodePoint(0x200c)) || // Zero-width non-joiner
    value.includes(String.fromCodePoint(0x200d)) || // Zero-width joiner
    value.includes(String.fromCodePoint(0xfeff)) // Zero-width no-break space
  ) {
    return true;
  }

  // Normalize for comparison
  const normalized = value.toLowerCase().replace(/\s+/g, "");

  // Check for URL protocols and only allow from our explicit allowlist
  const protocolMatch = normalized.match(/^([a-z0-9.+-]+):/i);
  if (protocolMatch) {
    const protocol = protocolMatch[1].toLowerCase() + ":";
    // If a protocol is found but it's not in our allowlist, reject it
    if (!ALLOWED_PROTOCOLS.has(protocol)) {
      return true;
    }
  }

  // Check for dangerous content patterns
  for (const pattern of DANGEROUS_CONTENT) {
    if (normalized.includes(pattern)) {
      return true;
    }
  }

  return false;
}

// No default export
