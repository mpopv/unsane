/**
 * unsane - A lightweight, zero-dependency HTML sanitization library
 *
 * This library provides HTML sanitization with:
 * - Small footprint (minimal bundle size)
 * - No dependencies (works in any JavaScript environment)
 * - Protection against XSS vectors
 * - Simple, streamlined API
 */

import { sanitize } from "./sanitizer/htmlSanitizer.js";
import { escape, encode, decode } from "./utils/htmlEntities.js";
import { SanitizerOptions, Sanitizer } from "./types.js";

// Export individual functions
export { sanitize, escape, encode, decode };

// Export types
export type { SanitizerOptions, Sanitizer };
