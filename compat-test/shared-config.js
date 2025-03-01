/**
 * Shared configuration for the sanitizer
 * This file exists to allow ESM compatibility tests to use the same defaults
 * as the main library without module system mismatches.
 * 
 * IMPORTANT: This file should be a direct copy of the default options from
 * /src/sanitizer/config.ts. Do not modify this file directly! Instead, update
 * the canonical configuration in config.ts and then sync this file to match.
 * 
 * The duplication issue will be addressed in a future refactoring that eliminates
 * the need for this duplicate configuration.
 */

export const DEFAULT_OPTIONS = {
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
  
  allowedAttributes: {
    // Links
    a: ["href", "name", "target", "rel"],
    
    // Images 
    img: ["src", "srcset", "alt", "title", "width", "height", "loading"],
    
    // Global attributes
    "*": ["id", "class", "title"]
  },
  
  // Always self-closing
};