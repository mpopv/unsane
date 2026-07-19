/**
 * HTML Entity handling utilities - simplified and unified version
 */

// Simple HTML entity maps - common entities only
const NAMED_TO_CHAR: Record<string, string> = {
  quot: '"',
  QUOT: '"',
  amp: "&",
  AMP: "&",
  lt: "<",
  LT: "<",
  gt: ">",
  GT: ">",
  apos: "'",
  nbsp: "\u00A0",
  colon: ":",
  lowbar: "_",
  NewLine: "\n",
  Tab: "\t",
};

const LEGACY_NAME_PATTERN = /^(?:AMP|GT|LT|QUOT|amp|gt|lt|nbsp|quot)$/;
const REFERENCE_PATTERN =
  /&(?:#(?:[xX][\dA-Fa-f]+|\d+);?|[0-9A-Za-z]+;?)/g;

const WINDOWS_1252_REPLACEMENTS =
  "€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008DŽ\u008F\u0090‘’“”•–—˜™š›œ\u009DžŸ";

const CHAR_TO_NAMED: Record<string, string> = {
  '"': "quot",
  "&": "amp",
  "<": "lt",
  ">": "gt",
  "'": "apos",
};

// Characters to always escape for security reasons
const ESCAPE_CHARS = /["'&<>`]/g;
/* eslint-disable no-control-regex */
const TEXT_NORMALIZE_PATTERN = /[\0-\x1f\x7f-\x9f"'&<>`]/g;
/* eslint-enable no-control-regex */

/**
 * Convert a code point to a string, handling surrogate pairs
 */
function codePointToString(codePoint: number): string {
  if (codePoint === 0 || codePoint > 0x10ffff) return "\uFFFD";
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) return "\uFFFD";

  if (codePoint >= 0x80 && codePoint <= 0x9f) {
    return WINDOWS_1252_REPLACEMENTS[codePoint - 0x80];
  }

  if (codePoint > 0xffff) {
    codePoint -= 0x10000;
    return String.fromCharCode(
      0xd800 + (codePoint >> 10),
      0xdc00 + (codePoint & 0x3ff),
    );
  }

  return String.fromCharCode(codePoint);
}

function decodeReference(
  reference: string,
  followingCharacter: string,
  attributeContext: boolean,
): string | undefined {
  const hasSemicolon = reference.endsWith(";");
  const entity = reference.slice(1, hasSemicolon ? -1 : undefined);

  if (entity[0] === "#") {
    const hexadecimal = entity[1] === "x" || entity[1] === "X";
    return codePointToString(
      parseInt(entity.slice(hexadecimal ? 2 : 1), hexadecimal ? 16 : 10),
    );
  }

  if (
    !hasSemicolon &&
    (!LEGACY_NAME_PATTERN.test(entity) ||
      (attributeContext && /[=0-9A-Za-z]/.test(followingCharacter)))
  ) {
    return undefined;
  }

  return NAMED_TO_CHAR[entity];
}

function normalizeReferences(
  text: string,
  normalizePlainText: (value: string) => string,
  attributeContext: boolean,
): string {
  let output = "";
  let lastIndex = 0;

  for (const match of text.matchAll(REFERENCE_PATTERN)) {
    const index = match.index;
    const reference = match[0];
    output += normalizePlainText(text.slice(lastIndex, index));

    const decoded = decodeReference(
      reference,
      text[index + reference.length] ?? "",
      attributeContext,
    );
    output +=
      decoded === undefined ? reference : normalizePlainText(decoded);
    lastIndex = index + reference.length;
  }

  return output + normalizePlainText(text.slice(lastIndex));
}

function escapeOnlyChar(char: string): string {
  if (char === "'") return "&#x27;";
  if (char === "`") return "&#x60;";
  return `&${CHAR_TO_NAMED[char]};`;
}

/**
 * Options for entity encoding
 */
export interface EncodeOptions {
  useNamedReferences?: boolean; // Use named entities like &lt; instead of &#x3C;
  decimal?: boolean; // Use decimal (&#38;) instead of hex (&#x26;)
  encodeEverything?: boolean; // Encode all characters, not just special ones
  escapeOnly?: boolean; // Only escape minimal set of security-sensitive characters
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
    escapeOnly = false,
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

  return String(text).replace(pattern, (char) => {
    // Skip non-target characters (should never happen because pattern limits matches)
    /* c8 ignore next */
    if (!escapeOnly && !encodeEverything && !/["&<>']/.test(char)) return char;

    // For escape function compatibility - use fixed output format for tests
    if (escapeOnly) {
      return escapeOnlyChar(char);
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
 * Decode numeric references and the compact named-reference subset used by
 * Unsane's public helpers and security checks.
 */
export function decode(text: string): string {
  if (!text) return "";

  return text.replace(REFERENCE_PATTERN, (reference, index: number) => {
    return (
      decodeReference(
        reference,
        text[index + reference.length] ?? "",
        false,
      ) ?? reference
    );
  });
}

/** Normalize references, remove controls, and escape inert text in one scan. */
export function normalizeText(text: string): string {
  return normalizeReferences(
    text,
    (value) =>
      value.replace(TEXT_NORMALIZE_PATTERN, (char) => {
        const code = char.charCodeAt(0);
        if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return "";
        return escapeOnlyChar(char);
      }),
    false,
  );
}

/** Preserve browser-recognized named references while safely quoting an attribute. */
export function normalizeAttributeValue(text: string): string {
  return normalizeReferences(
    text,
    (value) => encode(value, { escapeOnly: true }),
    true,
  );
}
