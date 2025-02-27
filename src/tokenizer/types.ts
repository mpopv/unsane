/**
 * HTML Token interfaces for the tokenizer
 */

export interface StartTagToken {
  type: "startTag";
  tagName: string;
  attrs: Array<{ name: string; value: string }>;
  selfClosing: boolean;
  raw: string; // entire original text
}

export interface EndTagToken {
  type: "endTag";
  tagName: string;
  raw: string;
}

export interface CommentToken {
  type: "comment";
  text: string;
  raw: string;
}

export interface TextToken {
  type: "text";
  text: string;
  raw: string;
}

export interface DoctypeToken {
  type: "doctype";
  name: string;
  publicId: string;
  systemId: string;
  raw: string;
}

export type HtmlToken =
  | StartTagToken
  | EndTagToken
  | CommentToken
  | TextToken
  | DoctypeToken;

// Tokenizer states for HTML parsing
export enum TokenizerState {
  DATA,
  TAG_OPEN,
  END_TAG_OPEN,
  TAG_NAME,
  END_TAG_NAME,
  BEFORE_ATTRIBUTE_NAME,
  ATTRIBUTE_NAME,
  AFTER_ATTRIBUTE_NAME,
  BEFORE_ATTRIBUTE_VALUE,
  ATTRIBUTE_VALUE_DOUBLE,
  ATTRIBUTE_VALUE_SINGLE,
  ATTRIBUTE_VALUE_UNQUOTED,
  SELF_CLOSING_START_TAG,
  COMMENT_START,
  COMMENT,
  COMMENT_END,
  DOCTYPE,
  DOCTYPE_BEFORE_NAME,
  DOCTYPE_NAME,
  DOCTYPE_AFTER_NAME,
  DOCTYPE_PUBLIC_OR_SYSTEM,
  DOCTYPE_PUBLIC_ID_SINGLE_QUOTED,
  DOCTYPE_PUBLIC_ID_DOUBLE_QUOTED,
  DOCTYPE_SYSTEM_ID_SINGLE_QUOTED,
  DOCTYPE_SYSTEM_ID_DOUBLE_QUOTED,
  DOCTYPE_BOGUS,
  RAWTEXT, // e.g. <script> until </script>
}

/**
 * List of tags that should be treated as raw text elements
 * and their contents should not be parsed as HTML
 */
export const RAWTEXT_TAGS = new Set(["script", "style", "xmp", "iframe", "noembed", "noframes"]);

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
  "wbr",
];

/**
 * Dangerous attributes that could be used for XSS
 */
export const DANGEROUS_ATTRS = [
  // Event handlers
  /^on\w+$/i,
  
  // Style can be used for XSS
  "style", 
  
  // URL-based attributes that could execute JavaScript
  "formaction",
  "xlink:href",
  "action",
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

export default {
  TokenizerState,
  RAWTEXT_TAGS,
  VOID_ELEMENTS,
  DANGEROUS_ATTRS,
  isDangerousAttribute
};