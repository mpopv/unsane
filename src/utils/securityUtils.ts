/**
 * Security utilities for HTML sanitization
 */

// Only these protocols are allowed (allowlist approach)
export const ALLOWED_PROTOCOLS = new Set(
  "http: https: mailto: tel: ftp: sms:".split(" "),
);

export const URL_ATTRIBUTES = new Set(
  "background cite href longdesc poster src usemap".split(" "),
);

// List of dangerous content patterns
export const DANGEROUS_CONTENT =
  "javascript eval( newfunction settimeout( setinterval( alert( confirm( prompt( document. window. onerror= onclick= onload= onmouseover=".split(
    " ",
  );

/* eslint-disable no-control-regex */
const URL_NORMALIZE_PATTERN =
  /&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]+);?|[\s\0-\x1f\x7f-\x9f\u200c-\u200f\ufeff]/gi;
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

function isUnsafeUrlCharacter(value: string): boolean {
  const code = value.charCodeAt(0);
  return (
    code <= 0x1f ||
    (code >= 0x7f && code <= 0x9f) ||
    (code >= 0x200c && code <= 0x200f) ||
    code === 0xfeff
  );
}

function normalizeUrl(value: string): string | undefined {
  let normalized = value;

  // Eight fused passes preserve the former decoder's maximum nested-entity
  // depth while collapsing its separate entity, control, and whitespace scans.
  for (let pass = 0; pass < 8; pass++) {
    // Stryker disable next-line BooleanLiteral: another bounded pass over an entity-free string produces the same normalized URL.
    let decodedEntity = false;
    let unsafe = false;

    normalized = normalized.replace(
      URL_NORMALIZE_PATTERN,
      (match, entity?: string) => {
        if (!entity) {
          unsafe ||= isUnsafeUrlCharacter(match);
          return "";
        }

        const entityName = entity.toLowerCase();
        const numeric = entityName[0] === "#";
        const hexadecimal = entityName[1] === "x";
        const decoded = numeric
          ? codePointToUrlChar(
              parseInt(
                entityName.slice(hexadecimal ? 2 : 1),
                hexadecimal ? 16 : 10,
              ),
              match,
            )
          : URL_NAMED_ENTITIES[entityName] || match;

        // Stryker disable next-line ConditionalExpression: reprocessing an unchanged entity only consumes the same fixed pass budget.
        if (decoded === match) return match;
        decodedEntity = true;
        unsafe ||= isUnsafeUrlCharacter(decoded);
        return /\s/.test(decoded) ? "" : decoded;
      },
    );

    if (unsafe) return undefined;
    // Stryker disable next-line ConditionalExpression: this only avoids redundant iterations within the same fixed eight-pass bound.
    if (!decodedEntity) break;
  }

  return normalized.toLowerCase();
}

export function isUrlAttribute(name: string): boolean {
  return URL_ATTRIBUTES.has(name.toLowerCase());
}

export function isSafeUrlAttributeValue(value: string): boolean {
  const normalized = normalizeUrl(value);
  if (normalized === undefined) return false;

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
