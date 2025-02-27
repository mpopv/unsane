/**
 * DOMPurify adapter for Unsane
 * This provides a DOMPurify-compatible interface for Unsane to check compatibility
 */

import { sanitize } from './direct-sanitizer.js';
import { decode, encode, escape } from './helpers.js';

// Create a minimal DOMPurify-like API
const UnsanePurify = () => {
  return {
    version: '0.1.0-unsane-compat',
    sanitize: (html, options = {}) => {
      // Convert DOMPurify options to Unsane options
      const unsaneOptions = {};
      
      // Handle ALLOWED_TAGS (DOMPurify) -> allowedTags (Unsane)
      if (options.ALLOWED_TAGS) {
        unsaneOptions.allowedTags = options.ALLOWED_TAGS;
      }
      
      // Handle ALLOWED_ATTR (DOMPurify) -> allowedAttributes (Unsane)
      if (options.ALLOWED_ATTR) {
        // DOMPurify uses a flat list of attributes, Unsane uses a map of tag -> attributes
        // For simplicity, we'll apply all attributes to all allowed tags
        unsaneOptions.allowedAttributes = {};
        const allTags = unsaneOptions.allowedTags || [
          "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "br", "b", "i", 
          "strong", "em", "a", "pre", "code", "img", "tt", "div", "ins", 
          "del", "sup", "sub", "p", "ol", "ul", "table", "thead", "tbody", 
          "tfoot", "blockquote", "dl", "dt", "dd", "kbd", "q", "samp", "var", 
          "hr", "ruby", "rt", "rp", "li", "tr", "td", "th", "s", "strike", 
          "summary", "details", "caption", "figure", "figcaption", "abbr", 
          "bdo", "cite", "dfn", "mark", "small", "span", "time", "wbr"
        ];
        
        allTags.forEach(tag => {
          unsaneOptions.allowedAttributes[tag] = options.ALLOWED_ATTR;
        });
      }
      
      // Handle RETURN_DOM and RETURN_DOM_FRAGMENT (return string for now)
      if (options.RETURN_DOM || options.RETURN_DOM_FRAGMENT) {
        console.warn('Unsane adapter: RETURN_DOM and RETURN_DOM_FRAGMENT are not supported');
      }
      
      // Handle WHOLE_DOCUMENT (not supported)
      if (options.WHOLE_DOCUMENT) {
        console.warn('Unsane adapter: WHOLE_DOCUMENT is not supported');
      }
      
      return sanitize(html, unsaneOptions);
    },
    removed: [], // DOMPurify tracks removed elements, we don't support this yet
    isSupported: true,
    addHook: () => {
      console.warn('Unsane adapter: addHook is not supported');
    },
    removeHook: () => {
      console.warn('Unsane adapter: removeHook is not supported');
    },
    setConfig: () => {
      console.warn('Unsane adapter: setConfig is not supported');
    },
    clearConfig: () => {
      console.warn('Unsane adapter: clearConfig is not supported');
    }
  };
};

// Create a fake window for testing
const fakeWindow = {
  document: {
    createElement: () => ({}), // Mock implementation
    getElementById: () => ({})  // Mock implementation
  }
};

export {
  UnsanePurify,
  fakeWindow,
  // Export the original Unsane functions
  sanitize,
  decode,
  encode,
  escape
};