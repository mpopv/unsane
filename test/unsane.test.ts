import { describe, it, expect } from 'vitest';
import { sanitize } from '../src/unsane';

describe('sanitize', () => {
  it('should remove disallowed tags', () => {
    const input = '<div>ok<script>alert("bad")</script></div>';
    const output = sanitize(input, { allowedTags: ['div'] });
    expect(output).toBe('<div>ok</div>');
  });

  it('should strip disallowed attributes', () => {
    const input = '<a href="https://example.com" onclick="alert(\'bad\')">Link</a>';
    const output = sanitize(input, { 
      allowedTags: ['a'],
      allowedAttributes: { 'a': ['href'] }
    });
    expect(output).toContain('href="https://example.com"');
    expect(output).not.toContain('onclick');
  });

  it('should properly handle self-closing tags', () => {
    const input = '<div><img src="test.jpg"><br></div>';
    const output = sanitize(input, { 
      allowedTags: ['div', 'img', 'br'],
      allowedAttributes: { 'img': ['src'] },
      selfClosing: true
    });
    expect(output).toContain('<img src="test.jpg" />');
    expect(output).toContain('<br />');
  });

  it('should handle malformed HTML', () => {
    const input = '<div><p>Unclosed paragraph<div>New div</div>';
    const output = sanitize(input, { allowedTags: ['div', 'p'] });
    // Should close p tag before opening new div
    expect(output).toBe('<div><p>Unclosed paragraph</p><div>New div</div></div>');
  });

  it('should use text transform when provided', () => {
    const input = '<p>hello world</p>';
    const output = sanitize(input, { 
      allowedTags: ['p'],
      transformText: (text) => text.toUpperCase()
    });
    expect(output).toBe('<p>HELLO WORLD</p>');
  });
});