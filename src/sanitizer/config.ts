/**
 * Default configuration for the HTML sanitizer
 * 
 * This is the canonical source of sanitizer configuration.
 * If you change anything here, make sure to update any duplicate
 * configurations elsewhere (e.g., in compat-test/shared-config.js).
 */

import { SanitizerOptions } from "../types";

/**
 * Default sanitizer options with minimal safe allowlists
 */
export const DEFAULT_OPTIONS: Required<SanitizerOptions> = {
  // Common HTML elements that are safe by default
  allowedTags: [
    // Headings
    "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8",
    
    // Basic text formatting
    "p", "div", "span", "b", "i", "strong", "em", 
    
    // Links and media
    "a", "img",
    
    // Lists
    "ul", "ol", "li", 
    
    // Tables
    "table", "thead", "tbody", "tfoot", "tr", "td", "th", 
    
    // Other common elements
    "br", "hr", "code", "pre", "blockquote",
    "dl", "dt", "dd", "kbd", "q", "samp", "var",
    "ruby", "rt", "rp", "s", "strike", "summary", 
    "details", "caption", "figure", "figcaption",
    "abbr", "bdo", "cite", "dfn", "mark", "small", "time", "wbr",
    "ins", "del", "sup", "sub", "tt"
  ],
  
  // Only the most essential attributes
  allowedAttributes: {
    // Links
    a: ["href", "name", "target", "rel"],
    
    // Images 
    img: ["src", "srcset", "alt", "title", "width", "height", "loading"],
    
    // Global attributes
    "*": ["id", "class", "title"]
  },
  
  // Always self-close void elements
};

// No default export