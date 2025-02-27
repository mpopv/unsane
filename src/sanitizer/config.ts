/**
 * Default configuration for the HTML sanitizer
 */

import { SanitizerOptions } from "../types";

/**
 * Default sanitizer options with safe allowlists
 */
export const DEFAULT_OPTIONS: Required<SanitizerOptions> = {
  allowedTags: [
    // Headings
    "h1", "h2", "h3", "h4", "h5", "h6",
    
    // Text formatting
    "b", "i", "strong", "em", "tt", "s", "strike", "small", "big", "mark",
    
    // Structure
    "p", "div", "span", "br", "hr",
    
    // Lists
    "ol", "ul", "li", "dl", "dt", "dd",
    
    // Links and media
    "a", "img",
    
    // Tables
    "table", "tbody", "thead", "tfoot", "tr", "td", "th", "caption",
    
    // Code
    "pre", "code", "samp", "kbd", "var",
    
    // Quotes and citations
    "blockquote", "q", "cite",
    
    // Inline semantic elements
    "abbr", "bdo", "dfn", "time", "wbr", 
    
    // Text decoration
    "ins", "del", "sup", "sub", 
    
    // Containers
    "summary", "details", "figure", "figcaption", "ruby", "rt", "rp",
  ],
  allowedAttributes: {
    // Links
    a: ["href", "name", "target", "rel", "title", "hreflang", "type"],
    
    // Images 
    img: ["src", "srcset", "alt", "title", "width", "height", "loading", "align"],
    
    // Allow specific global attributes
    "*": ["id", "class", "lang", "dir", "title", "translate"],
    
    // Tables
    table: ["width", "border", "align", "cellspacing", "cellpadding"],
    th: ["scope", "colspan", "rowspan", "align", "valign"],
    td: ["colspan", "rowspan", "align", "valign"],
    
    // Other element-specific attributes
    ol: ["type", "start"],
    li: ["value"],
    abbr: ["title"],
    time: ["datetime"],
    q: ["cite"],
    blockquote: ["cite"],
  },
  selfClosing: true,
  transformText: (text) => text,
};

/**
 * Additional dangerous attribute values that should be filtered
 */
export const DANGEROUS_ATTR_VALUES = [
  "javascript:",
  "data:",
  "vbscript:",
  "file:",
  "alert(",
  "confirm(",
  "prompt(",
  "eval(",
  "Function(",
  "setTimeout(",
  "setInterval(",
  "onerror=",
  "onclick=",
  "expression(",
];

/**
 * Check if an attribute value is suspicious
 * @param value Attribute value to check
 * @returns True if the value contains suspicious content
 */
export function hasDangerousValue(value: string): boolean {
  if (!value) return false;
  
  const normalized = value.toLowerCase();
  
  return DANGEROUS_ATTR_VALUES.some(pattern => normalized.includes(pattern)) ||
         normalized.match(/[\u0000-\u001F]/) !== null; // Check for control characters
}

export default {
  DEFAULT_OPTIONS,
  DANGEROUS_ATTR_VALUES,
  hasDangerousValue,
};