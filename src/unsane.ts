import { decode, encode } from "./utils/htmlEntities";

/**
 * Configuration options for the HTML sanitizer
 */
export interface SanitizerOptions {
  /**
   * List of HTML tags allowed in sanitized output
   */
  allowedTags?: string[];

  /**
   * Object mapping tag names to allowed attributes
   */
  allowedAttributes?: Record<string, string[]>;

  /**
   * If true, self-closing tags will always have a closing slash
   */
  selfClosing?: boolean;

  /**
   * Hook to transform text nodes before encoding
   */
  transformText?: (text: string) => string;
}

/**
 * Default sanitizer configuration
 */
const defaultOptions: SanitizerOptions = {
  allowedTags: [
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "h7",
    "h8",
    "br",
    "b",
    "i",
    "strong",
    "em",
    "a",
    "pre",
    "code",
    "img",
    "tt",
    "div",
    "ins",
    "del",
    "sup",
    "sub",
    "p",
    "ol",
    "ul",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "blockquote",
    "dl",
    "dt",
    "dd",
    "kbd",
    "q",
    "samp",
    "var",
    "hr",
    "ruby",
    "rt",
    "rp",
    "li",
    "tr",
    "td",
    "th",
    "s",
    "strike",
    "summary",
    "details",
    "caption",
    "figure",
    "figcaption",
    "abbr",
    "bdo",
    "cite",
    "dfn",
    "mark",
    "small",
    "span",
    "time",
    "wbr",
  ],
  allowedAttributes: {
    a: ["href", "name", "target", "rel"],
    img: ["src", "srcset", "alt", "title", "width", "height", "loading"],
  },
  selfClosing: true,
};

/**
 * Parses HTML string into a series of tokens
 */
function parseHTML(html: string): string[] {
  const tokens: string[] = [];
  let position = 0;

  while (position < html.length) {
    const char = html[position];

    if (char === "<") {
      // Look for tag end
      const tagEnd = html.indexOf(">", position);
      if (tagEnd === -1) {
        // No closing '>', treat rest as text
        tokens.push(html.slice(position));
        break;
      } else {
        // Extract tag including <>
        tokens.push(html.slice(position, tagEnd + 1));
        position = tagEnd + 1;
      }
    } else {
      // Extract text until next tag or end
      const nextTag = html.indexOf("<", position);
      if (nextTag === -1) {
        // No more tags, treat rest as text
        tokens.push(html.slice(position));
        break;
      } else {
        tokens.push(html.slice(position, nextTag));
        position = nextTag;
      }
    }
  }

  return tokens;
}

/**
 * Determines if a token is an opening tag
 */
function isOpeningTag(token: string): boolean {
  return (
    token.startsWith("<") &&
    !token.startsWith("</") &&
    !token.endsWith("/>") &&
    !token.startsWith("<!--") &&
    !token.startsWith("<!") &&
    !token.startsWith("<?")
  );
}

/**
 * Determines if a token is a self-closing tag
 */
function isSelfClosingTag(token: string): boolean {
  return token.startsWith("<") && token.endsWith("/>");
}

/**
 * Determines if a token is a closing tag
 */
function isClosingTag(token: string): boolean {
  return token.startsWith("</");
}

/**
 * Extracts tag name from a tag token
 */
function getTagName(token: string): string {
  if (isOpeningTag(token) || isSelfClosingTag(token)) {
    const match = token.match(/<([a-zA-Z0-9-]+)(?:\s|\/|>)/);
    return match ? match[1].toLowerCase() : "";
  } else if (isClosingTag(token)) {
    const match = token.match(/<\/([a-zA-Z0-9-]+)>/);
    return match ? match[1].toLowerCase() : "";
  }
  return "";
}

/**
 * Sanitizes HTML by removing disallowed tags and attributes
 */
export function sanitize(html: string, userOpts?: SanitizerOptions): string {
  const options = { ...defaultOptions, ...userOpts };
  const {
    allowedTags = [],
    allowedAttributes = {},
    selfClosing = true,
    transformText,
  } = options;

  // Parse HTML into tokens
  const tokens = parseHTML(html);
  const stack: string[] = [];
  let output = "";

  for (const token of tokens) {
    if (token.startsWith("<") && !token.startsWith("<!--")) {
      // Handle tags
      if (isOpeningTag(token) || isSelfClosingTag(token)) {
        const tagName = getTagName(token);

        if (allowedTags.includes(tagName)) {
          // Process allowed tag
          if (isOpeningTag(token)) {
            // Check if we need to close any incompatible tags first
            if (tagName === "div" && stack.includes("p")) {
              const pIndex = stack.lastIndexOf("p");
              // Close the p tag and any tags nested inside it
              for (let i = stack.length - 1; i >= pIndex; i--) {
                output += `</${stack[i]}>`;
              }
              // Remove closed tags from stack
              stack.splice(pIndex);
            }

            stack.push(tagName);

            // Clean attributes
            const cleanedAttrs = processAttributes(
              token,
              tagName,
              allowedAttributes
            );
            output += `<${tagName}${cleanedAttrs}>`;
          } else {
            // Self-closing tag
            // Clean attributes
            const cleanedAttrs = processAttributes(
              token,
              tagName,
              allowedAttributes
            );
            output += `<${tagName}${cleanedAttrs}${selfClosing ? " />" : ">"}`;
          }
        }
      } else if (isClosingTag(token)) {
        const tagName = getTagName(token);

        if (allowedTags.includes(tagName)) {
          // Find matching opening tag in stack
          const index = stack.lastIndexOf(tagName);

          if (index !== -1) {
            // Close all nested tags properly
            for (let i = stack.length - 1; i >= index; i--) {
              output += `</${stack[i]}>`;
            }

            // Remove closed tags from stack
            stack.splice(index);
          }
        }
      }
    } else {
      // Text content
      const text = transformText ? transformText(token) : token;
      // Only decode and encode text if it's not empty
      if (text.trim()) {
        output += encode(decode(text));
      }
    }
  }

  // Close any remaining tags
  for (let i = stack.length - 1; i >= 0; i--) {
    output += `</${stack[i]}>`;
  }

  return output;
}

/**
 * Process and filter attributes for a tag
 */
function processAttributes(
  token: string,
  tagName: string,
  allowedAttributes: Record<string, string[]>
): string {
  const allowedAttrs = allowedAttributes[tagName] || [];
  let result = "";

  // Parse attributes with a more robust regex
  const attrRegex = /(\w+)(?:=(?:["']([^"']*)["']|([^\s>]*))?)?/g;
  let match;

  // Skip the tag name at the beginning of the token
  const tokenContent = token.slice(token.indexOf(tagName) + tagName.length);

  while ((match = attrRegex.exec(tokenContent)) !== null) {
    const [, name, quotedValue, unquotedValue] = match;

    if (allowedAttrs.includes(name)) {
      const value = quotedValue !== undefined ? quotedValue : unquotedValue;

      if (value !== undefined) {
        result += ` ${name}="${value}"`;
      } else {
        result += ` ${name}`;
      }
    }
  }

  return result;
}

// Create index file
export { sanitize as default };
