/**
 * Public interfaces for the HTML sanitizer
 */

export interface SanitizerOptions {
  /**
   * Array of allowed HTML tag names
   */
  allowedTags?: string[];

  /**
   * Object mapping tag names to arrays of allowed attribute names
   * A special "*" key can be used for attributes allowed on all elements
   */
  allowedAttributes?: Record<string, string[]>;

  // All configuration options above
}

export interface Sanitizer {
  /**
   * Sanitize HTML string, removing potentially dangerous content
   * @param html HTML to sanitize
   * @param options Optional configuration options
   * @returns Sanitized HTML string
   */
  sanitize: (html: string, options?: SanitizerOptions) => string;
}