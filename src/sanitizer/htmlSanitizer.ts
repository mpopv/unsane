/**
 * HTML Sanitizer - Removes dangerous content from HTML
 * 
 * Uses an inline tokenizer to parse HTML and rebuild it safely in a single pass
 */

import { VOID_ELEMENTS, isDangerousAttribute } from "../tokenizer/types";
import { DEFAULT_OPTIONS } from "./config";
import { SanitizerOptions } from "../types";
import { encode, decode, escape } from "../utils/htmlEntities";
import { containsDangerousContent, sanitizeTextContent } from "../utils/securityUtils";

/**
 * Process and filter attributes for a tag, removing any dangerous attributes
 * 
 * @param attrs Array of attributes as [name, value] pairs
 * @param tagName The tag name
 * @param allowedAttributesMap Map of tag names to allowed attributes
 * @returns String of sanitized attributes
 */
function processAttributes(
  attrs: Array<[string, string]>,
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
  for (const [name, value] of attrs) {
    const lowerName = name.toLowerCase();

    // Skip the attribute if it's not in the allowlist or it's a dangerous attribute pattern
    if (!allowedAttrs.includes(lowerName) || isDangerousAttribute(lowerName)) {
      continue;
    }
    
    // Always remove event handlers and style attributes - they're too risky
    if (lowerName.startsWith('on') || lowerName === 'style') {
      continue;
    }

    // Filter attributes with dangerous URLs or values
    if (value && containsDangerousContent(value)) {
      // Remove the attribute completely for href/src/etc.
      if (lowerName === "href" || lowerName === "src" || lowerName === "action" || 
          lowerName === "formaction" || lowerName === "xlink:href") {
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
      result += ` ${lowerName}="${escape(value)}"`;
    } else {
      result += ` ${lowerName}`;
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
  
  // Stack for tracking open tags
  const stack: string[] = [];
  
  // Output buffer
  let output = "";
  
  // Parse state management
  let position = 0;
  let textBuffer = '';
  
  // A simple state machine for parsing
  const STATE = {
    TEXT: 0,
    TAG_START: 1,
    TAG_NAME: 2,
    TAG_END: 3,
    ATTR_NAME: 4,
    ATTR_VALUE_START: 5,
    ATTR_VALUE: 6
  };
  
  let state = STATE.TEXT;
  let tagNameBuffer = '';
  let attrNameBuffer = '';
  let attrValueBuffer = '';
  let isClosingTag = false;
  let inQuote = '';
  let currentAttrs: Array<[string, string]> = [];
  let isSelfClosing = false;
  
  // Helper function to emit text
  function emitText() {
    if (textBuffer) {
      const text = mergedOptions.transformText 
        ? mergedOptions.transformText(textBuffer) 
        : textBuffer;
      
      // Only encode non-empty text
      if (text.trim() || text.includes(" ")) {
        // Remove any control characters directly
        const cleanText = text.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
        
        if (cleanText.includes("&")) {
          // Text already contains entities - sanitize carefully
          const decoded = decode(cleanText);
          output += sanitizeTextContent(decoded, encode);
        } else {
          // Regular text - encode to prevent XSS
          output += encode(cleanText);
        }
      }
      
      textBuffer = '';
    }
  }
  
  // Function to handle a start tag
  function handleStartTag(tagName: string, attrs: Array<[string, string]>, selfClosing: boolean) {
    if (mergedOptions.allowedTags.includes(tagName)) {
      // Handle void elements and self-closing tags
      if (VOID_ELEMENTS.includes(tagName) || selfClosing) {
        const attrsStr = processAttributes(
          attrs,
          tagName,
          mergedOptions.allowedAttributes
        );
        
        // Use self-closing format if configured
        if (mergedOptions.selfClosing) {
          output += `<${tagName}${attrsStr} />`;
        } else {
          output += `<${tagName}${attrsStr}></${tagName}>`;
        }
      } else {
        // Regular opening tag - add to stack
        stack.push(tagName);
        const attrsStr = processAttributes(
          attrs,
          tagName,
          mergedOptions.allowedAttributes
        );
        output += `<${tagName}${attrsStr}>`;
      }
    }
  }
  
  // Function to handle an end tag
  function handleEndTag(tagName: string) {
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
  }
  
  // Main parsing loop
  while (position < html.length) {
    const char = html[position];
    
    switch (state) {
      case STATE.TEXT:
        if (char === '<') {
          emitText();
          
          // Special handling for double <<, which could be malformed HTML used for XSS
          if (html[position + 1] === '<') {
            // Skip the second < and emit it as text
            textBuffer = '<';
            emitText();
            position++; // Skip the second <
          }
          
          state = STATE.TAG_START;
        } else {
          textBuffer += char;
        }
        break;
        
      case STATE.TAG_START:
        if (char === '/') {
          isClosingTag = true;
          state = STATE.TAG_NAME;
        } else if (char === '!') {
          // Check if this is a comment, and if so, handle special cases
          if (html.slice(position, position + 3) === '!--') {
            // This is a HTML comment
            
            // Special handling for conditional comments which might contain script tags
            if (html.slice(position + 3).indexOf('[if') !== -1) {
              // Find the end of the comment
              const commentEnd = html.indexOf('-->', position);
              if (commentEnd !== -1) {
                position = commentEnd + 2; // Will be incremented at end of loop
              } else {
                position = html.length - 1;
              }
              state = STATE.TEXT;
              continue;
            }
            
            // Regular comment - find closing '-->' tag and skip
            const commentEnd = html.indexOf('-->', position);
            if (commentEnd !== -1) {
              position = commentEnd + 2; // Will be incremented at end of loop
            } else {
              position = html.length - 1;
            }
          } else {
            // Handle doctype - find closing '>' and skip
            const gtIndex = html.indexOf('>', position);
            if (gtIndex !== -1) {
              position = gtIndex; // Will be incremented at end of loop
            } else {
              position = html.length - 1;
            }
          }
          state = STATE.TEXT;
        } else if (/[a-zA-Z]/.test(char)) {
          tagNameBuffer = char.toLowerCase();
          
          // Special handling for script tags - they should be skipped
          if (!isClosingTag && tagNameBuffer === 's' && html.slice(position, position + 6).toLowerCase() === 'script') {
            // Find position of tag closing
            let endPos = position;
            while (endPos < html.length && html[endPos] !== '>') {
              endPos++;
            }
            
            if (endPos < html.length) {
              // We found the end of the opening script tag
              // Now we need to capture any text content that comes before the script
              const textBeforeScript = html.slice(0, position - 1); // Up to the '<' that started the script tag
              const lastTextTagEnd = textBeforeScript.lastIndexOf('>');
              
              if (lastTextTagEnd !== -1) {
                const textContent = textBeforeScript.slice(lastTextTagEnd + 1);
                if (textContent.trim()) {
                  textBuffer = textContent;
                  emitText();
                }
              }
              
              // Skip to the closing script tag
              const scriptEnd = html.indexOf('</script>', endPos);
              if (scriptEnd !== -1) {
                position = scriptEnd + 8; // Move past </script>
              } else {
                position = html.length; 
              }
              state = STATE.TEXT;
              continue;
            }
          }
          
          state = STATE.TAG_NAME;
          currentAttrs = [];
          isSelfClosing = false;
        } else {
          // Not a valid tag, revert to text
          textBuffer += '<' + char;
          state = STATE.TEXT;
        }
        break;
        
      case STATE.TAG_NAME:
        if (/[a-zA-Z0-9\-_]/.test(char)) {
          tagNameBuffer += char.toLowerCase();
        } else if (/\s/.test(char)) {
          state = STATE.ATTR_NAME;
        } else if (char === '>') {
          if (isClosingTag) {
            handleEndTag(tagNameBuffer);
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
          }
          
          tagNameBuffer = '';
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        } else if (char === '/' && !isClosingTag) {
          isSelfClosing = true;
          state = STATE.TAG_END;
        }
        break;
      
      case STATE.ATTR_NAME:
        if (/[a-zA-Z0-9\-_:]/.test(char)) {
          attrNameBuffer += char.toLowerCase();
        } else if (char === '=') {
          state = STATE.ATTR_VALUE_START;
        } else if (/\s/.test(char)) {
          if (attrNameBuffer) {
            // Boolean attribute with no value
            currentAttrs.push([attrNameBuffer, '']);
            attrNameBuffer = '';
          }
        } else if (char === '>') {
          if (attrNameBuffer) {
            // Add the attribute without a value
            currentAttrs.push([attrNameBuffer, '']);
            attrNameBuffer = '';
          }
          
          if (isClosingTag) {
            handleEndTag(tagNameBuffer);
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
          }
          
          tagNameBuffer = '';
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        } else if (char === '/' && !isClosingTag) {
          if (attrNameBuffer) {
            // Add the final attribute
            currentAttrs.push([attrNameBuffer, '']);
            attrNameBuffer = '';
          }
          
          isSelfClosing = true;
          state = STATE.TAG_END;
        }
        break;
        
      case STATE.ATTR_VALUE_START:
        if (char === '"' || char === "'") {
          inQuote = char;
          attrValueBuffer = '';
          state = STATE.ATTR_VALUE;
        } else if (/\s/.test(char)) {
          // Just skip whitespace
        } else if (char === '>') {
          // Attribute with empty value
          currentAttrs.push([attrNameBuffer, '']);
          attrNameBuffer = '';
          
          if (isClosingTag) {
            handleEndTag(tagNameBuffer);
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
          }
          
          tagNameBuffer = '';
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        } else {
          // Unquoted attribute value
          attrValueBuffer = char;
          state = STATE.ATTR_VALUE;
        }
        break;
        
      case STATE.ATTR_VALUE:
        if (inQuote && char === inQuote) {
          // End of quoted attribute
          currentAttrs.push([attrNameBuffer, attrValueBuffer]);
          attrNameBuffer = '';
          attrValueBuffer = '';
          inQuote = '';
          state = STATE.ATTR_NAME;
        } else if (!inQuote && /[\s>]/.test(char)) {
          // End of unquoted attribute
          currentAttrs.push([attrNameBuffer, attrValueBuffer]);
          attrNameBuffer = '';
          attrValueBuffer = '';
          
          if (char === '>') {
            if (isClosingTag) {
              handleEndTag(tagNameBuffer);
            } else {
              handleStartTag(tagNameBuffer, currentAttrs, isSelfClosing);
            }
            
            tagNameBuffer = '';
            currentAttrs = [];
            isClosingTag = false;
            isSelfClosing = false;
            state = STATE.TEXT;
          } else {
            state = STATE.ATTR_NAME;
          }
        } else {
          attrValueBuffer += char;
        }
        break;
        
      case STATE.TAG_END:
        if (char === '>') {
          if (isClosingTag) {
            handleEndTag(tagNameBuffer);
          } else {
            handleStartTag(tagNameBuffer, currentAttrs, true);
          }
          
          tagNameBuffer = '';
          currentAttrs = [];
          isClosingTag = false;
          isSelfClosing = false;
          state = STATE.TEXT;
        }
        break;
    }
    
    position++;
  }
  
  // Handle any remaining text
  emitText();
  
  // Close any remaining tags
  for (let i = stack.length - 1; i >= 0; i--) {
    output += `</${stack[i]}>`;
  }
  
  return output;
}

export default {
  sanitize
};