import { describe, it, expect } from 'vitest';
import { sanitize } from '../src/sanitizer/htmlSanitizer';

describe('Text Content Preservation', () => {
  it('should preserve text content inside elements', () => {
    const input = '<div>Hello world</div>';
    const output = sanitize(input);
    console.log('Input:', input);
    console.log('Output:', output);
    expect(output).toContain('Hello world');
  });
  
  it('should apply text transformation', () => {
    const input = '<p>hello world</p>';
    const output = sanitize(input, {
      transformText: (text) => text.toUpperCase()
    });
    console.log('Input with transform:', input);
    console.log('Output with transform:', output);
    expect(output).toContain('HELLO WORLD');
  });
  
  it('should show text when parsing unclosed elements', () => {
    const input = '<div><p>Unclosed paragraph<div>New div</div>';
    const output = sanitize(input);
    console.log('Unclosed input:', input);
    console.log('Unclosed output:', output);
    expect(output).toContain('Unclosed paragraph');
    expect(output).toContain('New div');
  });
});