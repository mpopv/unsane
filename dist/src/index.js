/**
 * unsane - A lightweight, zero-dependency HTML sanitization library
 *
 * This library provides HTML sanitization with:
 * - Small footprint (minimal bundle size)
 * - No dependencies (works in any JavaScript environment)
 * - Protection against XSS vectors
 * - Simple, streamlined API
 */
import { sanitize } from "./sanitizer/htmlSanitizer";
import { escape, encode, decode } from "./utils/htmlEntities";
// Export individual functions
export { sanitize, escape, encode, decode };
