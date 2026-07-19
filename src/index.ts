/** Public API for Unsane's DOM-free HTML sanitization helpers. */

export { createSanitizer, sanitize } from "./sanitizer/htmlSanitizer.js";
export { escape, encode, decode } from "./utils/htmlEntities.js";
export type {
  CompiledSanitizer,
  SanitizerOptions,
  Sanitizer,
} from "./types.js";
