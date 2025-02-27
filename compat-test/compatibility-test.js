/**
 * Compatibility test between Unsane and DOMPurify
 * This runs a subset of DOMPurify's own tests against Unsane
 */

import { UnsanePurify, fakeWindow } from './dompurify-adapter.js';
import assert from 'assert';
import { describe, it } from 'node:test';

// Create an instance of the DOMPurify-compatible API
const DOMPurify = UnsanePurify(fakeWindow);

// Custom assert.contains function similar to QUnit's
assert.contains = function(actual, expected) {
  if (Array.isArray(expected)) {
    // Check if actual matches any of the expected values
    const matches = expected.some(exp => actual === exp);
    if (!matches) {
      throw new Error(`Expected ${actual} to be one of ${expected.join(', ')}`);
    }
  } else {
    // Check if actual contains expected
    if (expected.indexOf(actual) === -1) {
      throw new Error(`Expected ${actual} to be contained in ${expected}`);
    }
  }
};

// Run tests
describe('Unsane DOMPurify compatibility tests', () => {
  // Basic sanitization tests
  describe('Basic sanitization', () => {
    it('should remove disallowed tags', () => {
      const input = '<div>ok<script>alert("bad")</script></div>';
      const output = DOMPurify.sanitize(input, { ALLOWED_TAGS: ['div'] });
      assert.equal(output, '<div>ok</div>');
    });

    it('should strip disallowed attributes', () => {
      const input = '<a href="https://example.com" onclick="alert(\'bad\')">Link</a>';
      const output = DOMPurify.sanitize(input, { 
        ALLOWED_TAGS: ['a'],
        ALLOWED_ATTR: ['href'] 
      });
      assert(output.includes('href="https://example.com"'));
      assert(!output.includes('onclick'));
    });

    it('should properly handle self-closing tags', () => {
      const input = '<div><img src="test.jpg"><br></div>';
      const output = DOMPurify.sanitize(input, { 
        ALLOWED_TAGS: ['div', 'img', 'br'],
        ALLOWED_ATTR: ['src']
      });
      assert(output.includes('<img src="test.jpg"'));
      assert(output.includes('<br'));
    });

    it('should handle malformed HTML', () => {
      const input = '<div><p>Unclosed paragraph<div>New div</div>';
      const output = DOMPurify.sanitize(input, { ALLOWED_TAGS: ['div', 'p'] });
      // Should close p tag before opening new div
      assert.equal(output, '<div><p>Unclosed paragraph</p><div>New div</div></div>');
    });
  });

  // XSS tests
  describe('XSS prevention', () => {
    it('should prevent script injection', () => {
      const input = '<a>123<script>alert(1)</script></a>';
      const output = DOMPurify.sanitize(input);
      assert.equal(output, '<a>123</a>');
    });

    it('should prevent event handler injection', () => {
      const input = '<img src="x" onerror="alert(1)">';
      const output = DOMPurify.sanitize(input);
      assert(!output.includes('onerror'));
      assert(output.includes('<img src="x"'));
    });

    it('should prevent JavaScript URLs', () => {
      const input = '<a href="javascript:alert(1)">click me</a>';
      const output = DOMPurify.sanitize(input);
      assert(!output.includes('javascript:'));
    });

    it('should handle Unicode XSS vectors', () => {
      const input = '<a href="jav\u0000ascript:alert(1)">xss</a>';
      const output = DOMPurify.sanitize(input);
      assert(!output.includes('javascript:'));
    });

    it('should handle data URI in links', () => {
      const input = '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">xss</a>';
      const output = DOMPurify.sanitize(input);
      assert(!output.includes('data:'));
    });
  });

  // Config options tests
  describe('Configuration options', () => {
    it('should respect ALLOWED_TAGS', () => {
      const input = '<div><b>text</b><script>alert(1)</script></div>';
      const output = DOMPurify.sanitize(input, { ALLOWED_TAGS: ['b'] });
      assert.equal(output, '<b>text</b>');
    });

    it('should respect ALLOWED_ATTR', () => {
      const input = '<div class="foo" id="bar" onclick="alert(1)">text</div>';
      const output = DOMPurify.sanitize(input, { 
        ALLOWED_TAGS: ['div'],
        ALLOWED_ATTR: ['class'] 
      });
      assert(output.includes('class="foo"'));
      assert(!output.includes('id='));
      assert(!output.includes('onclick='));
    });
  });

  // HTML entity tests
  describe('HTML entity handling', () => {
    it('should correctly handle HTML entities in attribute values', () => {
      const input = '<div title="&quot;quoted text&quot;">text</div>';
      const output = DOMPurify.sanitize(input, { 
        ALLOWED_TAGS: ['div'],
        ALLOWED_ATTR: ['title'] 
      });
      assert(output.includes('title="&quot;quoted text&quot;"') || output.includes('title="\\"quoted text\\""'));
    });
    
    it('should correctly handle HTML entities in text content', () => {
      const input = '<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>';
      const output = DOMPurify.sanitize(input);
      // The result should not have unescaped the entities into actual tags
      assert(!output.includes('<script>'));
      assert(output.includes('&lt;script&gt;') || output.includes('&lt;script>'));
    });
  });

  // Complex cases
  describe('Complex cases', () => {
    it('should handle complex nested tags', () => {
      const input = '<div><p><span>Text <b>bold</b> <i>italic</i></span></p></div>';
      const output = DOMPurify.sanitize(input);
      assert(output.includes('<div><p><span>Text <b>bold</b> <i>italic</i></span></p></div>'));
    });

    it('should handle SVG (if supported)', () => {
      const input = '<svg width="100" height="100"><circle cx="50" cy="50" r="40" /></svg>';
      // SVG support is optional in Unsane, so we just check if the output is reasonable
      const output = DOMPurify.sanitize(input, { ALLOWED_TAGS: ['svg', 'circle'] });
      
      // Either it keeps the SVG or removes it entirely, both are acceptable for this test
      if (output.includes('<svg')) {
        assert(output.includes('<circle'));
      } else {
        assert(output === '');
      }
    });
  });
});