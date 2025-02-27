/**
 * HTML Token interfaces for the simplified tokenizer
 */

/**
 * Start tag token with attributes
 */
export interface StartTagToken {
  type: "startTag";
  tagName: string;
  attrs: Array<{ name: string; value: string }>;
  selfClosing: boolean;
}

/**
 * End tag token
 */
export interface EndTagToken {
  type: "endTag";
  tagName: string;
}

/**
 * Text token
 */
export interface TextToken {
  type: "text";
  text: string;
}

/**
 * HTML token types
 */
export type HtmlToken = StartTagToken | EndTagToken | TextToken;

/**
 * List of void elements that should be self-closing
 */
export const VOID_ELEMENTS = [
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr"
];

/**
 * Dangerous attributes that could be used for XSS
 */
export const DANGEROUS_ATTRS = [
  // Event handlers
  /^on\w+$/i,
  
  // Style can be used for XSS
  "style", 
  
  // Form actions
  "formaction",
  
  // URL-based attributes that could execute JavaScript
  "xlink:href",
  "action"
];

/**
 * Check if an attribute name matches any dangerous patterns
 */
export function isDangerousAttribute(name: string): boolean {
  name = name.toLowerCase();
  
  for (const pattern of DANGEROUS_ATTRS) {
    if (typeof pattern === 'string') {
      if (name === pattern) return true;
    } else if (pattern.test(name)) {
      return true;
    }
  }
  
  return false;
}

// No default export