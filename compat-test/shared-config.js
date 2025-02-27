/**
 * Shared configuration for the sanitizer
 * This file exists to allow ESM compatibility tests to use the same defaults
 * as the main library without module system mismatches.
 * 
 * During build optimizations, we identified that having duplicate DEFAULT_OPTIONS
 * negatively impacts bundle size, so we maintain this file to keep configurations
 * aligned while working around ESM/CJS interoperability limitations.
 * 
 * IMPORTANT: If you change the configuration in /src/sanitizer/config.ts,
 * make sure to update this file as well to keep them in sync.
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
    "*": ["id", "class"]
  },
  
  selfClosing: true,
  transformText: (text) => text,
};