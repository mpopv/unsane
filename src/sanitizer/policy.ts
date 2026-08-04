import { DEFAULT_OPTIONS } from "./config.js";
import type { SanitizerOptions } from "../types.js";
import {
  decode,
  escape,
  normalizeAttributeValue,
} from "../utils/htmlEntities.js";
import {
  isSafeUrlAttributeValue,
  isUrlAttribute,
} from "../utils/securityUtils.js";

export type ParsedAttribute = [name: string, value: string, hasValue: boolean];

export interface CompiledPolicy {
  allowedTags: Set<string>;
  allowedAttributes: Map<string, Set<string>>;
  maxInputLength: number;
}

type SerializedAttribute = [
  name: string,
  value: string,
  hasValue: boolean,
  serializedValue?: string,
];

// eslint-disable-next-line no-control-regex
const UNSAFE_ATTRIBUTE_CHARS_PATTERN = /[\0-\x1f\x7f-\x9f\u200c-\u200f\ufeff]/;
const UNSUPPORTED_ELEMENTS = new Set(
  "base body form head html link meta".split(" "),
);
const UNSUPPORTED_ATTRIBUTES = new Set(
  "accesskey attributionsrc autofocus commandfor form formaction formenctype formmethod formnovalidate formtarget http-equiv imagesrcset is nonce ping popover popovertarget popovertargetaction slot srcdoc srcset style tabindex xmlns".split(
    " ",
  ),
);

function invalid(name: string): never {
  throw new TypeError(`Invalid ${name}.`);
}

function normalizeStringList(values: unknown, optionName: string): Set<string> {
  if (!Array.isArray(values)) invalid(optionName);

  const normalized = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") invalid(optionName);
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
    invalid("allowedAttributes");
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

function normalizePolicy(options?: SanitizerOptions): CompiledPolicy {
  if (
    options !== undefined &&
    (typeof options !== "object" || options === null || Array.isArray(options))
  ) {
    invalid("options");
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

const DEFAULT_POLICY = normalizePolicy();

export function compilePolicy(options?: SanitizerOptions): CompiledPolicy {
  return options === undefined ? DEFAULT_POLICY : normalizePolicy(options);
}

export function assertValidInput(
  html: unknown,
  maxInputLength: number,
): asserts html is string {
  if (typeof html !== "string") invalid("html");

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

export function isAllowedElement(
  tagName: string,
  policy: CompiledPolicy,
): boolean {
  return (
    policy.allowedTags.has(tagName) &&
    !UNSUPPORTED_ELEMENTS.has(tagName) &&
    !tagName.includes("-")
  );
}

function isUnsupportedAttribute(name: string): boolean {
  return (
    UNSUPPORTED_ATTRIBUTES.has(name) ||
    name.startsWith("on") ||
    name.startsWith("xlink:") ||
    name.startsWith("xmlns:")
  );
}

function safeTarget(value: string): "_blank" | "_self" | undefined {
  const target = value.trim().toLowerCase();
  return target === "_blank" || target === "_self" ? target : undefined;
}

function mergeSafeRel(value: string): string {
  const relTokens = value
    .split(/\s+/)
    .map((token) => token.toLowerCase())
    .filter((token) => token && token !== "opener");

  for (const requiredToken of ["noopener", "noreferrer"]) {
    if (!relTokens.includes(requiredToken)) relTokens.push(requiredToken);
  }

  return relTokens.join(" ");
}

export function serializeAttributes(
  attributes: ParsedAttribute[],
  tagName: string,
  policy: CompiledPolicy,
): string {
  const tagAllowedAttributes = policy.allowedAttributes.get(tagName);
  const globalAttributes = policy.allowedAttributes.get("*");
  const output: SerializedAttribute[] = [];
  const emitted = new Set<string>();
  let hasBlankTarget = false;

  for (let [name, value, hasValue] of attributes) {
    const rawValue = value;
    value = decode(value);

    if (
      (!tagAllowedAttributes?.has(name) && !globalAttributes?.has(name)) ||
      isUnsupportedAttribute(name)
    ) {
      continue;
    }

    const urlAttribute = isUrlAttribute(name);
    if (urlAttribute) {
      if (!isSafeUrlAttributeValue(value)) continue;
    } else if (value && UNSAFE_ATTRIBUTE_CHARS_PATTERN.test(value)) {
      continue;
    }

    if (emitted.has(name)) continue;
    emitted.add(name);

    if (name === "target" && hasValue) {
      const target = safeTarget(value);
      if (!target) continue;
      value = target;
      hasBlankTarget = target === "_blank";
    }

    output.push([
      name,
      value,
      hasValue,
      urlAttribute || name === "target" || name === "rel"
        ? undefined
        : normalizeAttributeValue(rawValue),
    ]);
  }

  if (tagName === "a" && hasBlankTarget) {
    const relAttribute = output.find(([name]) => name === "rel");
    if (relAttribute) {
      relAttribute[1] = mergeSafeRel(relAttribute[1]);
      relAttribute[3] = undefined;
    } else {
      output.push(["rel", "noopener noreferrer", true]);
    }
  }

  return output
    .map(([name, value, hasValue, serializedValue]) =>
      hasValue ? ` ${name}="${serializedValue ?? escape(value)}"` : ` ${name}`,
    )
    .join("");
}
