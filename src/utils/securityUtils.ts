/**
 * Security utilities for HTML sanitization
 */

// Only these protocols are allowed (allowlist approach)
export const ALLOWED_PROTOCOLS = new Set(
  "http: https: mailto: tel: ftp: sms:".split(" "),
);

export const URL_ATTRIBUTES = new Set(
  "archive background cite classid codebase data dynsrc href itemid longdesc lowsrc manifest poster profile src usemap".split(
    " ",
  ),
);

/* eslint-disable no-control-regex */
const URL_NORMALIZE_PATTERN =
  /&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]+);?|[\s\0-\x1f\x7f-\x9f\u200c-\u200f\ufeff]/gi;
/* eslint-enable no-control-regex */

const URL_NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  colon: ":",
  newline: "\n",
  nbsp: " ",
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
        const namedEntity = URL_NAMED_ENTITIES[entityName];
        const decoded = numeric
          ? codePointToUrlChar(
              parseInt(
                entityName.slice(hexadecimal ? 2 : 1),
                hexadecimal ? 16 : 10,
              ),
              match,
            )
          : typeof namedEntity === "string"
            ? namedEntity
            : match;

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
