/**
 * unsane - A lightweight, zero-dependency HTML sanitization library
 *
 * Main entry point that exports the public API
 */
import { sanitize } from './sanitizer/htmlSanitizer';
import { escape, encode, decode } from './utils/htmlEntities';
import { SanitizerOptions, Sanitizer } from './types';
declare const sanitizer: Sanitizer;
export { sanitize, escape, encode, decode };
export type { SanitizerOptions, Sanitizer };
export default sanitizer;
