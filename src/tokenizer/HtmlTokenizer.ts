/**
 * Simplified HTML Tokenizer
 * 
 * This is a streamlined HTML tokenizer that prioritizes correctly handling text content.
 */

import { HtmlToken, StartTagToken, EndTagToken, TextToken } from "./types";

/**
 * Tokenize HTML into a sequence of tokens
 * 
 * @param html HTML string to parse
 * @returns Array of HTML tokens
 */
export function tokenizeHTML(html: string): HtmlToken[] {
  const tokens: HtmlToken[] = [];
  let position = 0;
  
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
  let textBuffer = '';
  let tagNameBuffer = '';
  let attrNameBuffer = '';
  let attrValueBuffer = '';
  let currentToken: Partial<StartTagToken | TextToken | EndTagToken> = {};
  let isClosingTag = false;
  let inQuote = '';
  
  // Helper function to emit a text token
  function emitText() {
    if (textBuffer) {
      tokens.push({
        type: 'text',
        text: textBuffer
      });
      textBuffer = '';
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
          // Check if this is a comment, and if so, we need to handle special cases
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
          currentToken = isClosingTag ? 
            { type: 'endTag', tagName: '' } : 
            { type: 'startTag', tagName: '', attrs: [], selfClosing: false };
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
          if (isClosingTag) {
            (currentToken as EndTagToken).tagName = tagNameBuffer;
          } else {
            (currentToken as StartTagToken).tagName = tagNameBuffer;
          }
          tagNameBuffer = '';
          state = STATE.ATTR_NAME;
        } else if (char === '>') {
          if (isClosingTag) {
            const endToken: EndTagToken = {
              type: 'endTag',
              tagName: tagNameBuffer
            };
            tokens.push(endToken);
          } else {
            (currentToken as StartTagToken).tagName = tagNameBuffer;
            tokens.push(currentToken as StartTagToken);
          }
          tagNameBuffer = '';
          currentToken = {};
          isClosingTag = false;
          state = STATE.TEXT;
        } else if (char === '/' && !isClosingTag) {
          (currentToken as StartTagToken).tagName = tagNameBuffer;
          (currentToken as StartTagToken).selfClosing = true;
          tagNameBuffer = '';
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
            if (!isClosingTag && currentToken.type === 'startTag') {
              (currentToken as StartTagToken).attrs.push({
                name: attrNameBuffer,
                value: ''
              });
            }
            attrNameBuffer = '';
          }
        } else if (char === '>') {
          if (attrNameBuffer) {
            // Add the attribute without a value
            if (!isClosingTag && currentToken.type === 'startTag') {
              (currentToken as StartTagToken).attrs.push({
                name: attrNameBuffer,
                value: ''
              });
            }
            attrNameBuffer = '';
          }
          
          if (isClosingTag) {
            const endToken: EndTagToken = {
              type: 'endTag',
              tagName: (currentToken as EndTagToken).tagName || ''
            };
            tokens.push(endToken);
          } else {
            tokens.push(currentToken as StartTagToken);
          }
          currentToken = {};
          isClosingTag = false;
          state = STATE.TEXT;
        } else if (char === '/' && !isClosingTag) {
          if (attrNameBuffer) {
            // Add the final attribute
            if (currentToken.type === 'startTag') {
              (currentToken as StartTagToken).attrs.push({
                name: attrNameBuffer,
                value: ''
              });
            }
            attrNameBuffer = '';
          }
          (currentToken as StartTagToken).selfClosing = true;
          state = STATE.TAG_END;
        }
        break;
        
      case STATE.ATTR_VALUE_START:
        if (char === '"' || char === "'") {
          inQuote = char;
          state = STATE.ATTR_VALUE;
        } else if (/\s/.test(char)) {
          // Just skip whitespace
        } else if (char === '>') {
          // Attribute with empty value
          if (!isClosingTag && currentToken.type === 'startTag') {
            (currentToken as StartTagToken).attrs.push({
              name: attrNameBuffer,
              value: ''
            });
          }
          attrNameBuffer = '';
          if (isClosingTag) {
            const endToken: EndTagToken = {
              type: 'endTag',
              tagName: (currentToken as EndTagToken).tagName || ''
            };
            tokens.push(endToken);
          } else {
            tokens.push(currentToken as StartTagToken);
          }
          currentToken = {};
          isClosingTag = false;
          state = STATE.TEXT;
        } else {
          // Unquoted attribute value
          attrValueBuffer += char;
          state = STATE.ATTR_VALUE;
        }
        break;
        
      case STATE.ATTR_VALUE:
        if (inQuote && char === inQuote) {
          // End of quoted attribute
          if (!isClosingTag && currentToken.type === 'startTag') {
            (currentToken as StartTagToken).attrs.push({
              name: attrNameBuffer,
              value: attrValueBuffer
            });
          }
          attrNameBuffer = '';
          attrValueBuffer = '';
          inQuote = '';
          state = STATE.ATTR_NAME;
        } else if (!inQuote && /[\s>]/.test(char)) {
          // End of unquoted attribute
          if (!isClosingTag && currentToken.type === 'startTag') {
            (currentToken as StartTagToken).attrs.push({
              name: attrNameBuffer,
              value: attrValueBuffer
            });
          }
          attrNameBuffer = '';
          attrValueBuffer = '';
          
          if (char === '>') {
            if (isClosingTag) {
              const endToken: EndTagToken = {
                type: 'endTag',
                tagName: (currentToken as EndTagToken).tagName || ''
              };
              tokens.push(endToken);
            } else {
              tokens.push(currentToken as StartTagToken);
            }
            currentToken = {};
            isClosingTag = false;
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
            const endToken: EndTagToken = {
              type: 'endTag',
              tagName: (currentToken as EndTagToken).tagName || ''
            };
            tokens.push(endToken);
          } else {
            tokens.push(currentToken as StartTagToken);
          }
          currentToken = {};
          isClosingTag = false;
          state = STATE.TEXT;
        }
        break;
    }
    
    position++;
  }
  
  // Handle any remaining text
  emitText();
  
  return tokens;
}

// No default export