/**
 * Security utilities for HTML sanitization
 */

// Interface for encoder options
export interface EncodeOptions {
  useNamedReferences?: boolean;
  encodeEverything?: boolean;
  decimal?: boolean;
  escapeOnly?: boolean;
}

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

/**
 * Sanitize text content by removing or encoding potentially dangerous patterns
 *
 * @param text Text to sanitize
 * @param encode Function to encode unsafe content
 * @returns Sanitized text
 */
export function sanitizeTextContent(
  text: string,
  encodeFunc?: (s: string, o?: EncodeOptions) => string
): string {
  if (!text) return "";

  // Simple regex pattern for common dangerous strings
  const dangerousPattern =
    /javascript|script|alert|eval|onerror|onclick|on\w+\s*=|\(\s*\)|function/gi;

  // Use the provided encode function or default to a basic encoder
  const encoder = encodeFunc || ((s: string) => s);

  return text.replace(dangerousPattern, (match) =>
    encoder(match, { useNamedReferences: true })
  );
}

// No default export
