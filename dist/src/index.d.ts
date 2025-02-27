/**
 * unsane - A lightweight, zero-dependency HTML sanitization library
 *
 * This library provides HTML sanitization with:
 * - Small footprint (minimal bundle size)
 * - No dependencies (works in any JavaScript environment)
 * - Protection against XSS vectors
 * - Simple, streamlined API
 */
import { sanitize } from './sanitizer/htmlSanitizer';
import { escape, encode, decode } from './utils/htmlEntities';
import { SanitizerOptions, Sanitizer } from './types';
declare const sanitizer: Sanitizer;
export { sanitize, escape, encode, decode };
export type { SanitizerOptions, Sanitizer };
export default sanitizer;
