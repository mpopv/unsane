/**
 * Default configuration for the HTML sanitizer
 */

import { SanitizerOptions } from "../types";

/**
 * Default sanitizer options with minimal safe allowlists
 */
export const DEFAULT_OPTIONS: Required<SanitizerOptions> = {
  // Common HTML elements that are safe by default
  allowedTags: [
    // Headings
    "h1", "h2", "h3", "h4", "h5", "h6",
    
    // Basic text formatting
    "p", "div", "span", "b", "i", "strong", "em", 
    
    // Links and media
    "a", "img",
    
    // Lists
    "ul", "ol", "li", 
    
    // Tables
    "table", "tr", "td", "th", 
    
    // Other common elements
    "br", "hr", "code", "pre", "blockquote"
  ],
  
  // Only the most essential attributes
  allowedAttributes: {
    // Links
    a: ["href", "target", "rel"],
    
    // Images 
    img: ["src", "alt", "width", "height"],
    
    // Global attributes
    "*": ["id", "class"]
  },
  
  selfClosing: true,
  transformText: (text) => text,
};

export default {
  DEFAULT_OPTIONS
};