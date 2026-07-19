/**
 * Security utilities for HTML sanitization
 */

import { decode } from "./htmlEntities.js";

// Only these protocols are allowed (allowlist approach)
export const ALLOWED_PROTOCOLS = new Set(
  "http: https: mailto: tel: ftp: sms:".split(" "),
);

export const URL_ATTRIBUTES = new Set(
  "href src cite poster action formaction xlink:href".split(" "),
);

// List of dangerous content patterns
export const DANGEROUS_CONTENT =
  "javascript eval( newfunction settimeout( setinterval( alert( confirm( prompt( document. window. onerror= onclick= onload= onmouseover=".split(
    " ",
  );

const HTML_ENTITY_PATTERN = /&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]+);?/gi;

/* eslint-disable no-control-regex */
const URL_OBFUSCATION_PATTERN = /[\0-\x1f\x7f-\x9f\u200c-\u200f\ufeff]/;
const STRIP_PROTOCOL_OBFUSCATION_PATTERN =
  /[\s\0-\x1f\x7f-\x9f\u200c-\u200f\ufeff]/g;
const DANGEROUS_OBFUSCATION_PATTERN =
  /(?:\\u0000|[\0-\x1f\x7f-\x9f\u200c-\u200d\ufeff])/;
/* eslint-enable no-control-regex */

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
  // Stryker disable next-line EqualityOperator: U+10FFFF and the unchanged entity are equally inert during scheme classification.
  if (codePoint > 0x10ffff) return fallback;
  return String.fromCodePoint(codePoint);
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
    // Stryker disable next-line ConditionalExpression: this only avoids redundant iterations within the same fixed four-pass bound.
    if (next === decoded) break;
    decoded = next;
  }

  return decoded;
}

export function isUrlAttribute(name: string): boolean {
  return URL_ATTRIBUTES.has(name.toLowerCase());
}

export function isSafeUrlAttributeValue(value: string): boolean {
  const decoded = decodeUrlEntities(value);

  if (URL_OBFUSCATION_PATTERN.test(decoded)) {
    return false;
  }

  const normalized = decoded
    .replace(STRIP_PROTOCOL_OBFUSCATION_PATTERN, "")
    .toLowerCase();

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
  if (DANGEROUS_OBFUSCATION_PATTERN.test(value)) {
    return true;
  }

  // Normalize for comparison
  // Stryker disable next-line Regex: replacing one whitespace at a time or an entire run produces the same normalized string.
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
