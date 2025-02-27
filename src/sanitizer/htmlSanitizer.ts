/**
 * HTML Sanitizer - Removes dangerous content from HTML
 * 
 * Uses tokenizer to parse HTML and rebuilds it without dangerous content
 */

import { tokenizeHTML } from "../tokenizer/HtmlTokenizer";
import { HtmlToken, StartTagToken, VOID_ELEMENTS, isDangerousAttribute } from "../tokenizer/types";
import { DEFAULT_OPTIONS, hasDangerousValue } from "./config";
import { SanitizerOptions } from "../types";
import { encode, decode, escape, isUnsafeUrl } from "../utils/htmlEntities";
import { sanitizeTextContent, sanitizeAggressively } from "../utils/textSecurity";

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
  
  // Combine the two lists (if global attributes are defined)
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

    // Filter potentially dangerous URLs 
    if ((name === "href" || name === "src" || name === "poster" || name === "action") && 
        typeof value === "string" && isUnsafeUrl(value)) {
      continue; // Skip this attribute
    }
    
    // Filter attributes with suspicious values
    if (typeof value === "string" && hasDangerousValue(value)) {
      continue; // Skip this attribute
    }

    // Special handling for attributes with HTML entities
    if (name === "title" && typeof value === "string" && value.includes("&quot;")) {
      // Keep the original entity encoding
      result += ` ${name}="${value}"`;
    } else if (value) {
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

  // Tokenize the HTML
  const tokens = tokenizeHTML(html);
  
  // Stack for tracking open tags
  const stack: string[] = [];
  
  // Output buffer
  let output = "";

  // Track if we should skip text content within a disallowed tag
  let skipUntilTag = "";
  let inSkippedTag = false;

  // Process each token
  for (const token of tokens) {
    // Skip content in disallowed tags (like script/style)
    if (inSkippedTag) {
      if (token.type === "endTag" && token.tagName === skipUntilTag) {
        inSkippedTag = false;
        skipUntilTag = "";
      }
      continue;
    }

    // Process tokens based on type
    switch (token.type) {
      case "startTag": {
        const tagName = token.tagName;

        if (mergedOptions.allowedTags.includes(tagName)) {
          if (!token.selfClosing) {
            // Special case for structural incompatibility: div inside p
            if (tagName === "div" && stack.includes("p")) {
              const pIndex = stack.lastIndexOf("p");

              // Close all tags up to and including the p tag
              for (let i = stack.length - 1; i >= pIndex; i--) {
                output += `</${stack[i]}>`;
              }

              // Remove closed tags from stack
              stack.splice(pIndex);
            }

            // Handle self-closing elements that are not explicitly self-closed
            if (
              VOID_ELEMENTS.includes(tagName) &&
              mergedOptions.selfClosing
            ) {
              const attrs = processAttributes(
                token,
                tagName,
                mergedOptions.allowedAttributes
              );
              output += `<${tagName}${attrs} />`;
            } else {
              // Add to stack and output opening tag
              stack.push(tagName);
              const attrs = processAttributes(
                token,
                tagName,
                mergedOptions.allowedAttributes
              );
              output += `<${tagName}${attrs}>`;
            }
          } else {
            // Handle explicit self-closing tag
            const attrs = processAttributes(
              token,
              tagName,
              mergedOptions.allowedAttributes
            );

            if (mergedOptions.selfClosing) {
              output += `<${tagName}${attrs} />`;
            } else {
              output += `<${tagName}${attrs}></${tagName}>`;
            }
          }
        } else {
          // Mark to skip content in disallowed tags like script and style
          if (tagName === "script" || tagName === "style" || tagName === "iframe") {
            inSkippedTag = true;
            skipUntilTag = tagName;
          }
        }
        break;
      }

      case "endTag": {
        const tagName = token.tagName;

        if (mergedOptions.allowedTags.includes(tagName)) {
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
          // Don't decode entities that are already encoded
          if (
            text.includes("&lt;") ||
            text.includes("&gt;") ||
            text.includes("&quot;") ||
            text.includes("&amp;")
          ) {
            // More thorough sanitization of already encoded content
            output += sanitizeTextContent(text);
          } else {
            // Filter for any script-like content
            const decoded = decode(text);
            if (decoded.match(/javascript|script|alert|onerror|onclick|eval|function|\(/i)) {
              // Use aggressive sanitization for potentially dangerous content
              output += sanitizeAggressively(decoded);
            } else {
              output += encode(decoded);
            }
          }
        }
        break;
      }

      case "comment":
        // Skip comments - they are unsafe in HTML
        break;

      case "doctype":
        // Skip doctype - not needed for sanitized content
        break;
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