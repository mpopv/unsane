/**
 * HTML Sanitizer - Removes dangerous content from HTML
 * 
 * Uses a simplified tokenizer to parse HTML and rebuilds it safely
 */

import { tokenizeHTML } from "../tokenizer/HtmlTokenizer";
import { HtmlToken, StartTagToken, VOID_ELEMENTS, isDangerousAttribute } from "../tokenizer/types";
import { DEFAULT_OPTIONS } from "./config";
import { SanitizerOptions } from "../types";
import { encode, decode, escape } from "../utils/htmlEntities";
import { containsDangerousContent, sanitizeTextContent } from "../utils/securityUtils";

/**
 * Process and filter attributes for a tag, removing any dangerous attributes
 * 
 * @param token The start tag token with attributes
 * @param tagName The tag name
 * @param allowedAttributesMap Map of tag names to allowed attributes
 * @returns String of sanitized attributes
 */
function processAttributes(
  token: StartTagToken,
  tagName: string,
  allowedAttributesMap: Record<string, string[]>
): string {
  // Get tag-specific allowed attributes
  const tagAllowedAttrs = allowedAttributesMap[tagName] || [];
  
  // Get global attributes (allowed for all tags)
  const globalAttrs = allowedAttributesMap["*"] || [];
  
  // Combine the two lists
  const allowedAttrs = [...tagAllowedAttrs, ...globalAttrs];
  
  let result = "";

  // Process each attribute
  for (const attr of token.attrs) {
    const name = attr.name.toLowerCase();
    const value = attr.value;

    // Skip the attribute if it's not in the allowlist or it's a dangerous attribute pattern
    if (!allowedAttrs.includes(name) || isDangerousAttribute(name)) {
      continue;
    }
    
    // Always remove event handlers and style attributes - they're too risky
    if (name.startsWith('on') || name === 'style') {
      continue;
    }

    // Filter attributes with dangerous URLs or values
    if (value && containsDangerousContent(value)) {
      // Remove the attribute completely for href/src/etc.
      if (name === "href" || name === "src" || name === "action" || 
          name === "formaction" || name === "xlink:href") {
        continue;
      }
      
      // For other attributes, try to sanitize the value
      // but remove any that still look suspicious
      if (value.toLowerCase().includes("javascript") || 
          value.toLowerCase().includes("script") ||
          value.toLowerCase().includes("alert") ||
          value.match(/[\u0000-\u001F\u200C-\u200F]/)) {
        continue;
      }
    }

    // Add the attribute to the output
    if (value) {
      result += ` ${name}="${escape(value)}"`;
    } else {
      result += ` ${name}`;
    }
  }

  return result;
}

/**
 * Main sanitizer function - takes HTML and returns sanitized HTML
 * 
 * @param html HTML string to sanitize
 * @param options Optional sanitizer configuration
 * @returns Sanitized HTML string
 */
export function sanitize(html: string, options?: SanitizerOptions): string {
  // Merge default options with user options
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options };

  // Tokenize the HTML - make sure we have an array of tokens
  const tokens = tokenizeHTML(html) || [];
  
  // Stack for tracking open tags
  const stack: string[] = [];
  
  // Output buffer
  let output = "";

  // Process each token
  for (const token of tokens) {
    switch (token.type) {
      case "startTag": {
        const tagName = token.tagName;

        if (mergedOptions.allowedTags.includes(tagName)) {
          // Handle void elements and self-closing tags
          if (VOID_ELEMENTS.includes(tagName) || token.selfClosing) {
            const attrs = processAttributes(
              token,
              tagName,
              mergedOptions.allowedAttributes
            );
            
            // Use self-closing format if configured
            if (mergedOptions.selfClosing) {
              output += `<${tagName}${attrs} />`;
            } else {
              output += `<${tagName}${attrs}></${tagName}>`;
            }
          } else {
            // Regular opening tag - add to stack
            stack.push(tagName);
            const attrs = processAttributes(
              token,
              tagName,
              mergedOptions.allowedAttributes
            );
            output += `<${tagName}${attrs}>`;
          }
        }
        break;
      }

      case "endTag": {
        const tagName = token.tagName;

        if (mergedOptions.allowedTags.includes(tagName) && !VOID_ELEMENTS.includes(tagName)) {
          // Find the matching opening tag in the stack
          const index = stack.lastIndexOf(tagName);

          if (index >= 0) {
            // Close all nested tags properly
            for (let i = stack.length - 1; i >= index; i--) {
              output += `</${stack[i]}>`;
            }

            // Remove closed tags from stack
            stack.splice(index);
          }
        }
        break;
      }

      case "text": {
        // Process text content
        const text = mergedOptions.transformText
          ? mergedOptions.transformText(token.text)
          : token.text;

        // Only encode non-empty text
        if (text.trim() || text.includes(" ")) {
          // Remove any control characters directly
          const cleanText = text.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
          
          if (cleanText.includes("&")) {
            // Text already contains entities - sanitize carefully
            // First decode, then sanitize and re-encode
            const decoded = decode(cleanText);
            output += sanitizeTextContent(decoded, encode);
          } else {
            // Regular text - encode to prevent XSS
            output += encode(cleanText);
          }
        }
        break;
      }
    }
  }

  // Close any remaining tags
  for (let i = stack.length - 1; i >= 0; i--) {
    output += `</${stack[i]}>`;
  }

  return output;
}

export default {
  sanitize
};