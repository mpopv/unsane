/**
 * HTML Sanitizer - Removes dangerous content from HTML
 *
 * Uses an inline tokenizer to parse HTML and rebuild it safely in a single pass
 *
 * Tokenizer invariants:
 * - Parsing advances left-to-right with an explicit state enum (TEXT, TAG_START,
 *   TAG_NAME, ATTR_NAME, ATTR_VALUE_START, ATTR_VALUE, TAG_END). Every state
 *   transition funnels through a single loop so we can reason about how
 *   malformed markup is repaired.
 * - Tag names and attribute names are normalized to lowercase before any
 *   allowlist check. Attribute/value pairs are buffered until the tag closes
 *   so that removal decisions are made on the complete attribute list.
 * - Text nodes are emitted only after entity decoding + re-encoding, which
 *   prevents double encoding while preserving text as inert text.
 * - `stack` tracks only allowed, non-void elements. Whenever structural
 *   anomalies are detected (e.g., `<div>` inside `<p>`), we eagerly close
 *   mismatched ancestors to keep the output tree balanced.
 * - Void elements (`br`, `img`, etc.) are emitted in `<tag />` form. Explicit
 *   self-closing syntax on non-void HTML elements is expanded to an opening and
 *   closing tag because browsers otherwise ignore the slash and keep the
 *   element open.
 */

import { DEFAULT_OPTIONS } from "./config.js";
import { SanitizerOptions } from "../types.js";
import { encode, decode } from "../utils/htmlEntities.js";
import {
  isSafeUrlAttributeValue,
  isUrlAttribute,
} from "../utils/securityUtils.js";

type Attribute = [name: string, value: string, hasValue: boolean];
type NormalizedOptions = {
  allowedTags: Set<string>;
  allowedAttributes: Map<string, Set<string>>;
  maxInputLength: number;
};
type OutputAttribute = [name: string, value: string, hasValue: boolean];

// Define void elements (tags that should be self-closing)
const VOID_ELEMENTS = new Set(
  "area base br col embed hr img input link meta param source track wbr".split(
    " ",
  ),
);

const SKIP_CONTENT_ELEMENTS = new Set(
  "script style iframe object embed template textarea title xmp noembed noframes noscript svg math".split(
    " ",
  ),
);

/* eslint-disable no-control-regex */
const CONTROL_CHARS_PATTERN = /[\0-\x1f\x7f-\x9f]/g;
const UNSAFE_ATTRIBUTE_CHARS_PATTERN = /[\0-\x1f\x7f-\x9f\u200c-\u200f\ufeff]/;
/* eslint-enable no-control-regex */
const DANGEROUS_ATTRIBUTE_PATTERN =
  /^(?:on|style$|formaction$|xlink:href$|action$)/;

function normalizeStringList(values: unknown, optionName: string): Set<string> {
  if (!Array.isArray(values)) {
    throw new TypeError(`Invalid ${optionName}.`);
  }

  const normalized = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") {
      throw new TypeError(`Invalid ${optionName}.`);
    }
    normalized.add(value.toLowerCase());
  }
  return normalized;
}

function normalizeAllowedAttributes(
  attributes: unknown,
): Map<string, Set<string>> {
  if (
    typeof attributes !== "object" ||
    attributes === null ||
    Array.isArray(attributes)
  ) {
    throw new TypeError("Invalid allowedAttributes.");
  }

  const normalized = new Map<string, Set<string>>();

  for (const [tagName, attrs] of Object.entries(attributes)) {
    const normalizedTagName = tagName.toLowerCase();
    const normalizedAttrs = normalized.get(normalizedTagName) ?? new Set();
    for (const attr of normalizeStringList(
      attrs,
      `allowedAttributes.${tagName}`,
    )) {
      normalizedAttrs.add(attr);
    }
    normalized.set(normalizedTagName, normalizedAttrs);
  }

  return normalized;
}

function normalizeOptions(options?: SanitizerOptions): NormalizedOptions {
  if (
    options !== undefined &&
    (typeof options !== "object" || options === null || Array.isArray(options))
  ) {
    throw new TypeError("Invalid options.");
  }

  return {
    allowedTags: normalizeStringList(
      options?.allowedTags === undefined
        ? DEFAULT_OPTIONS.allowedTags
        : options.allowedTags,
      "allowedTags",
    ),
    allowedAttributes: normalizeAllowedAttributes(
      options?.allowedAttributes === undefined
        ? DEFAULT_OPTIONS.allowedAttributes
        : options.allowedAttributes,
    ),
    maxInputLength:
      options?.maxInputLength === undefined
        ? DEFAULT_OPTIONS.maxInputLength
        : options.maxInputLength,
  };
}

function readTagName(html: string, position: number): string {
  let end = position + 1;
  while (end < html.length && /[a-zA-Z0-9\-_]/.test(html[end])) {
    end++;
  }
  return html.slice(position, end).toLowerCase();
}

function findTagEnd(html: string, position: number): number {
  const tagEnd = html.indexOf(">", position);
  return tagEnd === -1 ? html.length - 1 : tagEnd;
}

function findElementContentEnd(
  html: string,
  tagName: string,
  openTagEnd: number,
  tagStart: number,
): number {
  if (html.slice(tagStart, openTagEnd).trimEnd().endsWith("/")) {
    return openTagEnd;
  }

  const closingTag = new RegExp(`</${tagName}`, "gi");
  closingTag.lastIndex = openTagEnd + 1;
  const closeTagStart = closingTag.exec(html)?.index ?? -1;

  if (closeTagStart === -1) {
    return html.length - 1;
  }

  return findTagEnd(html, closeTagStart);
}

function shouldSkipElementContent(tagName: string): boolean {
  return SKIP_CONTENT_ELEMENTS.has(tagName) || tagName.startsWith("script");
}

function assertInputWithinLimit(html: string, maxInputLength: number): void {
  if (
    typeof maxInputLength !== "number" ||
    maxInputLength < 0 ||
    Number.isNaN(maxInputLength)
  ) {
    throw new RangeError("maxInputLength must be a non-negative number.");
  }

  if (Number.isFinite(maxInputLength) && html.length > maxInputLength) {
    throw new RangeError(
      `Input length ${html.length} exceeds maxInputLength ${maxInputLength}.`,
    );
  }
}

function isBlankTarget(value: string): boolean {
  return value.trim().toLowerCase() === "_blank";
}

function mergeSafeRel(value: string): string {
  const relTokens = value
    .split(/\s+/)
    .map((token) => token.toLowerCase())
    .filter(Boolean);

  for (const requiredToken of ["noopener", "noreferrer"]) {
    if (!relTokens.includes(requiredToken)) {
      relTokens.push(requiredToken);
    }
  }

  return relTokens.join(" ");
}

function renderAttribute([name, value, hasValue]: OutputAttribute): string {
  if (hasValue) {
    return ` ${name}="${encode(value, { escapeOnly: true })}"`;
  }

  return ` ${name}`;
}

/**
 * Process and filter attributes for a tag, removing any dangerous attributes
 *
 * @param attrs Array of attributes as [name, value] pairs
 * @param tagName The tag name
 * @param allowedAttributesMap Map of tag names to allowed attributes
 * @returns String of sanitized attributes
 */
function processAttributes(
  attrs: Attribute[],
  tagName: string,
  allowedAttributesMap: Map<string, Set<string>>,
): string {
  // Get tag-specific allowed attributes
  const tagAllowedAttrs = allowedAttributesMap.get(tagName);

  // Get global attributes (allowed for all tags)
  const globalAttrs = allowedAttributesMap.get("*");

  const outputAttrs: OutputAttribute[] = [];
  const emittedAttrs = new Set<string>();
  let hasBlankTarget = false;

  // Process each attribute
  for (const [name, value, hasValue] of attrs) {
    const lowerName = name.toLowerCase();

    // Skip the attribute if it's not in the allowlist or it's a dangerous attribute pattern
    if (
      (!tagAllowedAttrs?.has(lowerName) && !globalAttrs?.has(lowerName)) ||
      DANGEROUS_ATTRIBUTE_PATTERN.test(lowerName)
    ) {
      continue;
    }

    // Filter URL-bearing attributes with URL-specific protocol normalization.
    if (isUrlAttribute(lowerName)) {
      if (!isSafeUrlAttributeValue(value)) {
        continue;
      }
    } else if (value && UNSAFE_ATTRIBUTE_CHARS_PATTERN.test(value)) {
      continue;
    }

    if (emittedAttrs.has(lowerName)) {
      continue;
    }
    emittedAttrs.add(lowerName);

    const outputValue =
      lowerName === "target" && hasValue && isBlankTarget(value)
        ? "_blank"
        : value;

    if (lowerName === "target" && isBlankTarget(outputValue)) {
      hasBlankTarget = true;
    }

    outputAttrs.push([lowerName, outputValue, hasValue]);
  }

  if (tagName === "a" && hasBlankTarget) {
    const relAttr = outputAttrs.find(([name]) => name === "rel");

    if (relAttr) {
      relAttr[1] = mergeSafeRel(relAttr[1]);
    } else {
      outputAttrs.push(["rel", "noopener noreferrer", true]);
    }
  }

  return outputAttrs.map((attr) => renderAttribute(attr)).join("");
}

/**
 * Main sanitizer function - takes HTML and returns sanitized HTML
 *
 * @param html HTML string to sanitize
 * @param options Optional sanitizer configuration
 * @returns Sanitized HTML string
 */
export function sanitize(html: string, options?: SanitizerOptions): string {
  if (typeof html !== "string") {
    throw new TypeError("Invalid html.");
  }

  const mergedOptions = normalizeOptions(options);
  assertInputWithinLimit(html, mergedOptions.maxInputLength);

  // Stack for tracking open tags
  const stack: string[] = [];
  const previousOpenTagIndexes: number[] = [];
  const lastOpenTagIndex = new Map<string, number>();

  // Output buffer
  const output: string[] = [];

  // Parse state management
  let position = 0;
  let textBuffer = "";

  // A simple state machine for parsing
  const STATE = {
    TEXT: 0,
    TAG_START: 1,
    TAG_NAME: 2,
    TAG_END: 3,
    ATTR_NAME: 4,
    ATTR_VALUE_START: 5,
    ATTR_VALUE: 6,
  };

  let state = STATE.TEXT;
  let tagNameBuffer = "";
  let attrNameBuffer = "";
  let attrValueBuffer = "";
  let isClosingTag = false;
  let inQuote = "";
  let currentAttrs: Attribute[] = [];
  let isSelfClosing = false;

  // Helper function to emit text
  function emitText() {
    if (textBuffer) {
      // No transformation, use text directly
      const text = textBuffer;

      // Only process non-empty text
      if (text.trim() || text.includes(" ")) {
        // Decode any entities, then re-encode as inert text
        // This handles both regular text and text with entities in one path
        const decoded = decode(text).replace(CONTROL_CHARS_PATTERN, "");
        output.push(encode(decoded, { escapeOnly: true }));
      }

      textBuffer = "";
    }
  }

  function openTagIndex(tagName: string): number {
    return lastOpenTagIndex.get(tagName) ?? -1;
  }

  function pushOpenTag(tagName: string): void {
    previousOpenTagIndexes.push(openTagIndex(tagName));
    lastOpenTagIndex.set(tagName, stack.length);
    stack.push(tagName);
  }

  function closeStackFrom(index: number): void {
    while (stack.length > index) {
      const openTag = stack.pop()!;
      output.push(`</${openTag}>`);

      const previousIndex = previousOpenTagIndexes.pop()!;
      if (previousIndex < 0) {
        lastOpenTagIndex.delete(openTag);
      } else {
        lastOpenTagIndex.set(openTag, previousIndex);
      }
    }
  }

  // Function to handle a start tag
  function handleStartTag(
    tagName: string,
    attrs: Attribute[],
    selfClosing: boolean,
  ) {
    // Skip dangerous raw-content and namespace containers entirely for security.
    if (shouldSkipElementContent(tagName)) {
      return;
    }

    if (mergedOptions.allowedTags.has(tagName)) {
      // Special handling for HTML structure - div inside p is invalid HTML
      if (tagName === "div") {
        const pIndex = openTagIndex("p");
        if (pIndex >= 0) {
          closeStackFrom(pIndex);
        }
      }

      const attrsStr = processAttributes(
        attrs,
        tagName,
        mergedOptions.allowedAttributes,
      );

      if (VOID_ELEMENTS.has(tagName)) {
        output.push(`<${tagName}${attrsStr} />`);
      } else if (selfClosing) {
        output.push(`<${tagName}${attrsStr}></${tagName}>`);
      } else {
        // Regular opening tag - add to stack
        pushOpenTag(tagName);
        output.push(`<${tagName}${attrsStr}>`);
      }
    }
  }

  // Function to handle an end tag
  function handleEndTag(tagName: string) {
    if (
      mergedOptions.allowedTags.has(tagName) &&
      !VOID_ELEMENTS.has(tagName)
    ) {
      // Find the matching opening tag in the stack
      const index = openTagIndex(tagName);

      if (index >= 0) {
        closeStackFrom(index);
      }
    }
  }

  // Main parsing loop
  while (position < html.length) {
    const char = html[position];

    switch (state) {
      case STATE.TEXT:
        if (char === "<") {
          emitText();

          // Special handling for double <<, which could be malformed HTML used for XSS
          if (html[position + 1] === "<") {
            // Skip the second < and emit it as text
            textBuffer = "<";
            emitText();
            position++; // Skip the second <
          }

          state = STATE.TAG_START;
        } else {
          textBuffer += char;
        }
        break;

      case STATE.TAG_START:
        if (char === "/") {
          isClosingTag = true;
          state = STATE.TAG_NAME;
        } else if (char === "!") {
          if (html.startsWith("!--", position)) {
            const commentEnd = html.indexOf("-->", position + 3);
            position = commentEnd === -1 ? html.length - 1 : commentEnd + 2;
          } else {
            position = findTagEnd(html, position);
          }
          state = STATE.TEXT;
        } else if (/[a-zA-Z]/.test(char)) {
          const potentialTagName = readTagName(html, position);

          if (!isClosingTag && shouldSkipElementContent(potentialTagName)) {
            const openTagEnd = findTagEnd(html, position);
            position =
              findElementContentEnd(
                html,
                potentialTagName,
                openTagEnd,
                position,
              ) + 1;
            state = STATE.TEXT;
            continue;
          }

          tagNameBuffer = char.toLowerCase();
          state = STATE.TAG_NAME;
          currentAttrs = [];
          isSelfClosing = false;
        } else {
          // Not a valid tag, revert to text
          textBuffer += "<" + char;
          state = STATE.TEXT;
        }
        break;

      case STATE.TAG_NAME:
        if (/[a-zA-Z0-9\-_]/.test(char)) {
          tagNameBuffer += char.toLowerCase();
        } else if (/\s/.test(char)) {
          state = STATE.ATTR_NAME;
        } else if (char === ">") {
          if (isClosingTag) {
            handleEndTag(tagNameBuffer);
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
          }

          tagNameBuffer = "";
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        } else if (char === "/" && !isClosingTag) {
          isSelfClosing = true;
          state = STATE.TAG_END;
        }
        break;

      case STATE.ATTR_NAME:
        if (/[a-zA-Z0-9\-_:]/.test(char)) {
          attrNameBuffer += char.toLowerCase();
        } else if (char === "=") {
          state = STATE.ATTR_VALUE_START;
        } else if (/\s/.test(char)) {
          if (attrNameBuffer) {
            // Boolean attribute with no value
            currentAttrs.push([attrNameBuffer, "", false]);
            attrNameBuffer = "";
          }
        } else if (char === ">") {
          if (attrNameBuffer) {
            // Add the attribute without a value
            currentAttrs.push([attrNameBuffer, "", false]);
            attrNameBuffer = "";
          }

          if (isClosingTag) {
            handleEndTag(tagNameBuffer);
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
          }

          tagNameBuffer = "";
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        } else if (char === "/" && !isClosingTag) {
          if (attrNameBuffer) {
            // Add the final attribute
            currentAttrs.push([attrNameBuffer, "", false]);
            attrNameBuffer = "";
          }

          isSelfClosing = true;
          state = STATE.TAG_END;
        }
        break;

      case STATE.ATTR_VALUE_START:
        if (char === '"' || char === "'") {
          inQuote = char;
          attrValueBuffer = "";
          state = STATE.ATTR_VALUE;
        } else if (/\s/.test(char)) {
          // Just skip whitespace
        } else if (char === ">") {
          // Attribute with empty value
          currentAttrs.push([attrNameBuffer, "", true]);
          attrNameBuffer = "";

          if (isClosingTag) {
            handleEndTag(tagNameBuffer);
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
          }

          tagNameBuffer = "";
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        } else {
          // Unquoted attribute value
          attrValueBuffer = char;
          state = STATE.ATTR_VALUE;
        }
        break;

      case STATE.ATTR_VALUE:
        if (inQuote && char === inQuote) {
          // End of quoted attribute
          currentAttrs.push([attrNameBuffer, attrValueBuffer, true]);
          attrNameBuffer = "";
          attrValueBuffer = "";
          inQuote = "";
          state = STATE.ATTR_NAME;
        } else if (!inQuote && /[\s>]/.test(char)) {
          // End of unquoted attribute
          currentAttrs.push([attrNameBuffer, attrValueBuffer, true]);
          attrNameBuffer = "";
          attrValueBuffer = "";

          if (char === ">") {
            if (isClosingTag) {
              handleEndTag(tagNameBuffer);
            } else {
              handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
            }

            tagNameBuffer = "";
            currentAttrs = [];
            isClosingTag = false;
            isSelfClosing = false;
            state = STATE.TEXT;
          } else {
            state = STATE.ATTR_NAME;
          }
        } else {
          attrValueBuffer += char;
        }
        break;

      case STATE.TAG_END:
        if (char === ">") {
          // TAG_END is only reached for self-closing tags; closing tags exit earlier.
          /* c8 ignore next */
          if (isClosingTag) {
            // Invariant: closing tags are handled in TAG_NAME/ATTR_NAME states.
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, true);
          }

          tagNameBuffer = "";
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        }
        break;
    }

    position++;
  }

  // Handle any remaining text
  emitText();

  // Close any remaining tags
  closeStackFrom(0);

  return output.join("");
}
