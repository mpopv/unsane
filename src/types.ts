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
   *
   * URL-bearing attributes use Unsane's fixed conservative protocol allowlist.
   */
  allowedAttributes?: Record<string, string[]>;

  /**
   * Maximum input string length accepted by sanitize().
   * Set to Infinity to disable the guardrail for trusted, bounded inputs.
   */
  maxInputLength?: number;
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

/** A sanitizer whose policy has already been normalized and compiled. */
export type CompiledSanitizer = (html: string) => string;
