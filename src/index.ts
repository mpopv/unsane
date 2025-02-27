/**
 * unsane - A lightweight, zero-dependency HTML sanitization library
 * 
 * Main entry point that exports the public API
 */

import { sanitize } from './sanitizer/htmlSanitizer';
import { escape, encode, decode } from './utils/htmlEntities';
import { SanitizerOptions, Sanitizer } from './types';

// Create default sanitizer
const sanitizer: Sanitizer = { sanitize };

// Export individual functions
export { sanitize, escape, encode, decode };

// Export types
export type { SanitizerOptions, Sanitizer };

// Default export for convenience
export default sanitizer;