/**
 * Direct implementation of sanitize for compatibility testing
 * Using the inlined tokenizer approach for better performance
 * 
 * IMPORTANT: This file should mirror the implementation in src/sanitizer/htmlSanitizer.ts
 * Any security fixes or improvements should be made in both places
 * until a proper refactoring merges these implementations.
 */

import { decode, encode, escape } from './helpers.js';
import { DEFAULT_OPTIONS } from './shared-config.js';

// Deep merge function for properly handling nested options
function deepMerge(target, source) {
  // If source is undefined or null, return a copy of target
  if (!source) {
    return { ...target };
  }

  // Create a new object to avoid mutating either input
  const result = { ...target };

  // Iterate through source properties
  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      const sourceValue = source[key];
      const targetValue = target[key];

      // Handle null case
      if (sourceValue === null) {
        result[key] = null;
        continue;
      }

      // If both values are objects and not arrays, merge them recursively
      if (
        typeof sourceValue === 'object' && 
        !Array.isArray(sourceValue) &&
        typeof targetValue === 'object' && 
        !Array.isArray(targetValue) &&
        targetValue !== null
      ) {
        result[key] = deepMerge(targetValue, sourceValue);
      } else {
        // For arrays and primitives, replace the value
        result[key] = sourceValue;
      }
    }
  }

  return result;
}

/**
 * Unified security checker - checks if an attribute is safe
 */
function checkAttributeSafety(name, value) {
  if (!name) return { safe: false, reason: "empty-name" };
  
  const lowerName = name.toLowerCase();
  
  // Check dangerous attribute patterns
  if (lowerName.startsWith('on') || // Event handlers
      lowerName === 'style' ||      // Style can be used for XSS
      lowerName === 'formaction' || // Form actions can be dangerous
      lowerName === 'xlink:href' || // Can contain javascript
      lowerName === 'action') {     // Can contain javascript
    return { safe: false, reason: "dangerous-attr-name" };
  }
  
  // Early return if there's no value to check
  if (!value) return { safe: true };
  
  // Normalize for comparison
  const normalized = value.toLowerCase().replace(/\s+/g, "");
  
  // URL attribute checks (use Set for faster lookups)
  const urlAttributes = new Set(["href", "src", "action", "formaction", "xlink:href"]);
  if (urlAttributes.has(lowerName)) {
    // Only these protocols are allowed (allowlist approach)
    const allowedProtocols = new Set([
      "http:", "https:", "mailto:", "tel:", "ftp:", "sms:"
    ]);
    
    // Check for URL protocols and only allow from our explicit allowlist
    const protocolMatch = normalized.match(/^([a-z0-9.+-]+):/i);
    if (protocolMatch) {
      const protocol = protocolMatch[1].toLowerCase() + ':';
      // If a protocol is found but it's not in our allowlist, reject it
      if (!allowedProtocols.has(protocol)) {
        return { safe: false, reason: "non-allowlisted-protocol" };
      }
    }
  }
  
  // Check for dangerous content patterns in all attributes (use Set for faster lookups)
  const dangerousPatterns = new Set([
    "javascript", "eval(", "new Function", "setTimeout(", "setInterval(",
    "alert(", "confirm(", "prompt(", "document.", "window.",
    "onerror=", "onclick=", "onload=", "onmouseover="
  ]);
  
  for (const pattern of dangerousPatterns) {
    if (normalized.includes(pattern.toLowerCase())) {
      return { safe: false, reason: "dangerous-content" };
    }
  }
  
  // Check for control characters and Unicode obfuscation
  if (normalized.includes("\\u0000") ||
      normalized.includes("\0") ||
      normalized.match(/[\u0000-\u001F]/) || // Control characters
      normalized.includes("\u200C") || // Zero-width non-joiner
      normalized.includes("\u200D") || // Zero-width joiner
      normalized.includes("\u2028") || // Line separator
      normalized.includes("\u2029") || // Paragraph separator
      normalized.includes("\uFEFF")    // Zero-width no-break space
  ) {
    return { safe: false, reason: "control-chars" };
  }
  
  return { safe: true };
}

/**
 * Process and filter attributes for a tag
 */
function processAttributes(
  attrs, 
  tagName, 
  allowedAttributesMap
) {
  // Get allowed attributes for this tag and global attributes
  const tagAllowedAttrs = allowedAttributesMap[tagName] || [];
  const globalAttrs = allowedAttributesMap["*"] || [];
  // Use Set for faster lookups
  const allowedAttrs = new Set([...tagAllowedAttrs, ...globalAttrs]);
  
  let result = "";

  for (const [name, value] of attrs) {
    const lowerName = name.toLowerCase();
    
    // Skip attributes not in the allowlist
    if (!allowedAttrs.has(lowerName)) {
      continue;
    }
    
    // Use the unified security check
    const securityCheck = checkAttributeSafety(lowerName, value);
    
    // Skip unsafe attributes
    if (!securityCheck.safe) {
      continue;
    }
    
    // Add the attribute to the output
    if (value) {
      result += ` ${lowerName}="${encode(value, { escapeOnly: true })}"`;
    } else {
      result += ` ${lowerName}`;
    }
  }
  
  return result;
}

/**
 * Sanitizes text content by encoding dangerous patterns
 */
function sanitizeTextContent(text) {
  if (!text) return "";

  // Simple regex pattern for common dangerous strings
  const dangerousPattern =
    /javascript|script|alert|eval|onerror|onclick|on\w+\s*=|\(\s*\)|function/gi;

  return text.replace(dangerousPattern, (match) =>
    encode(match, { useNamedReferences: true })
  );
}

/**
 * Main sanitizer function using the inline tokenizer approach
 */
export function sanitize(html, options = {}) {
  // Deep merge for proper handling of nested objects
  const mergedOptions = deepMerge(DEFAULT_OPTIONS, options);
  
  // Stack for tracking open tags
  const stack = [];
  
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
  
  // List of void elements that should be self-closing (as Set for faster lookups)
  const VOID_ELEMENTS = new Set([
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr"
  ]);
  
  let state = STATE.TEXT;
  let tagNameBuffer = '';
  let attrNameBuffer = '';
  let attrValueBuffer = '';
  let isClosingTag = false;
  let inQuote = '';
  let currentAttrs = [];
  let isSelfClosing = false;
  
  // Helper function to emit text
  function emitText() {
    if (textBuffer) {
      // No transformation, use text directly
      const text = textBuffer;
      
      // Only process non-empty text
      if (text.trim() || text.includes(" ")) {
        // Remove any control characters directly
        const cleanText = text.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
        
        // Decode any entities, then sanitize and re-encode
        const decoded = decode(cleanText);
        output += sanitizeTextContent(decoded);
      }
      
      textBuffer = '';
    }
  }
  
  // Function to handle a start tag
  function handleStartTag(tagName, attrs, selfClosing) {
    // Skip any script tags entirely for security
    if (tagName === 'script') {
      return;
    }
    
    if (mergedOptions.allowedTags.includes(tagName)) {
      // Special handling for HTML structure - div inside p is invalid HTML
      if (tagName === "div" && stack.includes("p")) {
        const pIndex = stack.lastIndexOf("p");
        
        // Close all tags up to and including the p tag
        for (let i = stack.length - 1; i >= pIndex; i--) {
          output += `</${stack[i]}>`;
        }
        
        // Remove closed tags from stack
        stack.splice(pIndex);
      }
      
      // Handle void elements and self-closing tags
      if (VOID_ELEMENTS.has(tagName) || selfClosing) {
        const attrsStr = processAttributes(
          attrs,
          tagName,
          mergedOptions.allowedAttributes
        );
        
        // Always use self-closing format
        output += `<${tagName}${attrsStr} />`;
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
  function handleEndTag(tagName) {
    if (mergedOptions.allowedTags.includes(tagName) && !VOID_ELEMENTS.has(tagName)) {
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
          // Simple handling for comments and doctypes - skip everything until the next '>'
          const gtIndex = html.indexOf('>', position);
          if (gtIndex !== -1) {
            position = gtIndex; // Will be incremented at end of loop
          } else {
            position = html.length - 1;
          }
          state = STATE.TEXT;
        } else if (/[a-zA-Z]/.test(char)) {
          tagNameBuffer = char.toLowerCase();
          
          // Special handling for script or style tags - skip them entirely
          if (!isClosingTag && (
              (tagNameBuffer === 's' && html.slice(position, position + 6).toLowerCase() === 'script') ||
              (tagNameBuffer === 's' && html.slice(position, position + 5).toLowerCase() === 'style')
          )) {
            // Find position of tag closing
            let endPos = position;
            while (endPos < html.length && html[endPos] !== '>') {
              endPos++;
            }
            
            if (endPos < html.length) {
              // Skip directly to the closing tag without parsing content
              const isScript = html.slice(position, position + 6).toLowerCase() === 'script';
              const closingTag = isScript ? '</script>' : '</style>';
              const tagEnd = html.indexOf(closingTag, endPos);
              
              if (tagEnd !== -1) {
                position = tagEnd + closingTag.length - 1; // Move past closing tag (will be incremented in the loop)
              } else {
                position = html.length - 1; 
              }
              // Resume parsing without emitting any script/style content
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