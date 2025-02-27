/**
 * XSS prevention tests for Unsane
 * Based on selected test cases from DOMPurify's test suite
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

// Selected test cases from DOMPurify's test suite
describe('Unsane XSS Prevention Tests', () => {
  // Basic XSS cases
  it('should handle basic XSS case', () => {
    const input = '<img src="x" onerror="alert(1)">';
    const output = DOMPurify.sanitize(input);
    assert(output.includes('<img src="x"'));
    assert(!output.includes('onerror'));
  });

  it('should handle JavaScript URI in href', () => {
    const input = '<a href="javascript:alert(1)">click me</a>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('javascript:'));
  });

  it('should handle script tags', () => {
    const input = '<script>alert(1)</script>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('<script>'));
  });

  it('should handle malformed HTML with script injection', () => {
    const input = '<div><p>safe<script>alert(1)</script></div>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('<script>'));
    // We only care that the tags and content are preserved, not exact format
    assert(output.includes('<div>') && output.includes('<p>') && output.includes('safe'));
  });

  // More complex XSS vectors
  it('should handle event handlers', () => {
    const input = '<div onclick="alert(1)" onmouseover="alert(2)">click me</div>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('onclick'));
    assert(!output.includes('onmouseover'));
    assert(output.includes('<div>click me</div>'));
  });

  it('should handle obfuscated javascript URIs', () => {
    const inputs = [
      '<a href="javascript:alert(1)">link</a>',
      '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">link</a>',
      '<a href="jav&#x0A;ascript:alert(1)">link</a>',
      '<a href="jav&#x09;ascript:alert(1)">link</a>',
      '<a href="jav\u0000ascript:alert(1)">link</a>',
      '<a href=" j a v a s c r i p t:alert(1)">link</a>'
    ];

    inputs.forEach(input => {
      const output = DOMPurify.sanitize(input);
      assert(!output.includes('javascript:'));
      assert(!output.includes('jav&#x0A;ascript:'));
      assert(!output.includes('jav&#x09;ascript:'));
    });
  });

  it('should handle script in attributes', () => {
    const inputs = [
      '<div title="javascript:alert(1)">hover me</div>',
      '<img src="x" title="onerror=\'alert(1)\'">',
      '<div data-foo="alert(1)" data-bar="alert(2)">data attribute</div>'
    ];

    inputs.forEach(input => {
      const output = DOMPurify.sanitize(input);
      assert(!output.includes('javascript:alert'));
      assert(!output.includes('onerror='));
    });
  });

  // Special cases
  it('should handle special HTML entities', () => {
    const input = '&lt;script&gt;alert(1)&lt;/script&gt;';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('<script>'));
  });

  it('should handle data URIs', () => {
    const input = '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click me</a>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('data:'));
  });

  it('should handle iframe elements', () => {
    const input = '<iframe src="javascript:alert(1)" name="alert(2)"></iframe>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('<iframe'));
  });

  it('should handle onclick attribute in various contexts', () => {
    const inputs = [
      '<a onclick="alert(1)">click me</a>',
      '<div onclick="alert(1)">click me</div>',
      '<button onclick="alert(1)">click me</button>'
    ];

    inputs.forEach(input => {
      const output = DOMPurify.sanitize(input);
      assert(!output.includes('onclick'));
    });
  });

  it('should handle SVG XSS vectors', () => {
    const input = '<svg><script>alert(1)</script></svg>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('<script>'));
  });

  // Complex nested XSS cases
  it('should handle nested script content', () => {
    const input = '<div>safe<script><script>alert(1)<\/script><\/script></div>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('<script>'));
    // We only care that the div and content are preserved
    assert(output.includes('<div>') && output.includes('safe'));
  });

  it('should handle complex nested XSS vector', () => {
    const input = '<div><img src="x" onerror="alert(1)" alt="test"><script>alert(2)</script></div>';
    const output = DOMPurify.sanitize(input);
    assert(!output.includes('onerror'));
    assert(!output.includes('<script>'));
    // We only care that the tags and attributes are preserved, not exact format
    assert(output.includes('<div>') && output.includes('<img') && 
           output.includes('src="x"') && output.includes('alt="test"'));
  });
});