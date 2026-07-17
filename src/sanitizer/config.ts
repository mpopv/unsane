/**
 * Default configuration for the HTML sanitizer
 */

import { SanitizerOptions } from "../types.js";

export const DEFAULT_MAX_INPUT_LENGTH = 1_000_000;

/**
 * Default sanitizer options with minimal safe allowlists
 */
export const DEFAULT_OPTIONS: Required<SanitizerOptions> = {
  // Common HTML elements that are safe by default
  allowedTags:
    "h1 h2 h3 h4 h5 h6 p div span b i strong em a img ul ol li table tr td th br hr code pre blockquote".split(
      " ",
    ),

  // Only the most essential attributes
  allowedAttributes: {
    // Links
    a: "href target rel".split(" "),

    // Images
    img: "src alt width height".split(" "),

    // Global attributes
    "*": "id class".split(" "),
  },

  maxInputLength: DEFAULT_MAX_INPUT_LENGTH,

  // Always self-close void elements
};

// No default export
