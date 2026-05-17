/**
 * Security utilities for HTML sanitization
 */

import { decode } from "./htmlEntities.js";

// Only these protocols are allowed (allowlist approach)
export const ALLOWED_PROTOCOLS = new Set([
  "http:",
  "https:",
  "mailto:",
  "tel:",
  "ftp:",
  "sms:",
]);

export const URL_ATTRIBUTES = new Set([
  "href",
  "src",
  "cite",
  "poster",
  "action",
  "formaction",
  "xlink:href",
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

const HTML_ENTITY_PATTERN = /&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]+);?/gi;

const URL_NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  apos: "'",
  colon: ":",
  gt: ">",
  lpar: "(",
  lt: "<",
  newline: "\n",
  nbsp: " ",
  quot: '"',
  rpar: ")",
  tab: "\t",
};

function codePointToUrlChar(codePoint: number, fallback: string): string {
  if (codePoint < 0 || codePoint > 0x10ffff) return fallback;
  return String.fromCodePoint(codePoint);
}

function isControlOrObfuscationChar(char: string): boolean {
  const code = char.charCodeAt(0);
  return (
    code <= 0x1f ||
    (code >= 0x7f && code <= 0x9f) ||
    (code >= 0x200c && code <= 0x200f) ||
    code === 0xfeff
  );
}

function hasControlOrObfuscationChars(value: string): boolean {
  return value.split("").some((char) => isControlOrObfuscationChar(char));
}

function stripProtocolObfuscationChars(value: string): string {
  return value
    .split("")
    .filter((char) => !/\s/.test(char) && !isControlOrObfuscationChar(char))
    .join("");
}

function decodeUrlEntitiesOnce(value: string): string {
  return decode(value).replace(HTML_ENTITY_PATTERN, (match, entity) => {
    const normalized = entity.toLowerCase();

    if (normalized.startsWith("#x")) {
      return codePointToUrlChar(parseInt(normalized.slice(2), 16), match);
    }

    if (normalized.startsWith("#")) {
      return codePointToUrlChar(parseInt(normalized.slice(1), 10), match);
    }

    return URL_NAMED_ENTITIES[normalized] || match;
  });
}

function decodeUrlEntities(value: string): string {
  let decoded = value;

  for (let pass = 0; pass < 4; pass++) {
    const next = decodeUrlEntitiesOnce(decoded);
    if (next === decoded) break;
    decoded = next;
  }

  return decoded;
}

export function isUrlAttribute(name: string): boolean {
  return URL_ATTRIBUTES.has(name.toLowerCase());
}

export function isSafeUrlAttributeValue(value: string): boolean {
  if (!value) return true;

  const decoded = decodeUrlEntities(value);

  if (hasControlOrObfuscationChars(decoded)) {
    return false;
  }

  const normalized = stripProtocolObfuscationChars(
    decoded.trim(),
  ).toLowerCase();

  if (normalized.startsWith("//")) {
    return false;
  }

  const protocolMatch = normalized.match(/^([a-z][a-z0-9.+-]*):/);
  return !protocolMatch || ALLOWED_PROTOCOLS.has(`${protocolMatch[1]}:`);
}

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
