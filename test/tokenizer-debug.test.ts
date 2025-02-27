import { describe, it, expect } from 'vitest';
import { tokenizeHTML } from '../src/tokenizer/HtmlTokenizer';

describe('Tokenizer Debug', () => {
  it('should properly tokenize basic text content', () => {
    const html = '<div>Hello world</div>';
    const tokens = tokenizeHTML(html);
    console.log('Tokens for basic text:', JSON.stringify(tokens, null, 2));
    
    // Verify we get a text token with the content
    const textTokens = tokens.filter(t => t.type === 'text');
    expect(textTokens.length).toBeGreaterThan(0);
    expect(textTokens[0].text).toBe('Hello world');
  });
  
  it('should tokenize text inside nested tags', () => {
    const html = '<div><p>Paragraph text</p><span>Span text</span></div>';
    const tokens = tokenizeHTML(html);
    console.log('Tokens for nested text:', JSON.stringify(tokens, null, 2));
    
    // Verify we get text tokens
    const textTokens = tokens.filter(t => t.type === 'text');
    expect(textTokens.length).toBeGreaterThan(0);
    expect(textTokens.some(t => t.text.includes('Paragraph'))).toBe(true);
    expect(textTokens.some(t => t.text.includes('Span'))).toBe(true);
  });
});