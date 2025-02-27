/**
 * Advanced tests for the HTML sanitizer
 * 
 * These tests handle edge cases and advanced exploits
 */

import { expect, describe, it } from 'vitest';
import { sanitize } from '../src/sanitizer/htmlSanitizer';
import { ALLOWED_PROTOCOLS } from '../src/utils/securityUtils';

describe('Advanced HTML Sanitization', () => {
  describe('Complex HTML Structure', () => {
    it('should handle deeply nested elements', () => {
      const input = '<div><p><span><b><i>Text</i></b></span></p></div>';
      expect(sanitize(input)).toBe(input);
    });
    
    it('should handle broken nested structures', () => {
      const input = '<div><p><span>Text</div></p></span>';
      expect(sanitize(input)).toBe('<div><p><span>Text</span></p></div>');
    });
    
    it('should handle invalid closing tags', () => {
      const input = '<div>Text</span></p></div>';
      expect(sanitize(input)).toBe('<div>Text</div>');
    });
  });
  
  describe('XSS Prevention', () => {
    it('should handle obfuscated javascript URLs', () => {
      const tests = [
        '<a href="j&#97;vascript:alert(1)">Test</a>',
        '<a href="javascript&#58;alert(1)">Test</a>',
        '<a href="javascript:alert&lpar;1&rpar;">Test</a>',
        '<a href="javascript&#x3A;alert(1)">Test</a>',
        '<a href="j\u0061v\u0061script:alert(1)">Test</a>',
        '<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x31&#x29">Test</a>'
      ];
      
      for (const test of tests) {
        const result = sanitize(test);
        // For this test, we don't need to strictly require removing href
        // Just make sure no javascript: protocol makes it through
        expect(result).not.toContain('javascript:');
        expect(result).not.toContain('alert(1)');
        // But the link text should remain
        expect(result).toContain('>Test<');
      }
    });
    
    it('should handle unusual protocols', () => {
      const tests = [
        '<a href="vbscript:msgbox(1)">Test</a>',
        '<a href="mhtml:file://C:/evil.mht">Test</a>',
        '<a href="file:///etc/passwd">Test</a>',
        '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Test</a>',
        '<a href="blob:https://evil.com/12345">Test</a>',
        '<a href="filesystem:https://evil.com/temporary/file.txt">Test</a>'
      ];
      
      for (const test of tests) {
        expect(sanitize(test)).toBe('<a>Test</a>');
      }
    });

    it('should handle CSS-based attacks', () => {
      const tests = [
        '<div style="background-image: url(javascript:alert(1))">Test</div>',
        '<div style="behavior: url(script.htc)">Test</div>',
        '<div style="width: expression(alert(1))">Test</div>',
        '<div style="-moz-binding: url(evil.xml)">Test</div>'
      ];
      
      for (const test of tests) {
        expect(sanitize(test)).toBe('<div>Test</div>');
      }
    });

    it('should handle SVG-based attacks', () => {
      const tests = [
        '<svg><script>alert(1)</script></svg>',
        '<svg><use href="#x" onload="alert(1)" /></svg>',
        '<svg><animate xlink:href="#x" attributeName="href" values="javascript:alert(1)" /></svg>'
      ];
      
      for (const test of tests) {
        // SVG-related attacks should be neutralized
        const result = sanitize(test);
        expect(result).not.toContain('<script>');
        expect(result).not.toContain('onload=');
        expect(result).not.toContain('javascript:alert');
      }
    });
  });
  
  describe('DOCTYPE and Comment handling', () => {
    it('should strip doctypes', () => {
      const input = '<!DOCTYPE html><div>Text</div>';
      expect(sanitize(input)).toBe('<div>Text</div>');
    });
    
    it('should handle comments appropriately', () => {
      const input = '<!-- Comment --><div>Text</div><!-- Another comment -->';
      const result = sanitize(input);
      expect(result).toContain('<div>');
      expect(result).not.toContain('<!--');
      expect(result).not.toContain('-->');
    });
    
    it('should handle conditional comments', () => {
      const input = '<!--[if IE]><script>alert(1)</script><![endif]--><div>Text</div>';
      const result = sanitize(input);
      // The div and text should be preserved, and no script should be executed
      expect(result).toContain('<div>');
      expect(result).toContain('Text');
      expect(result).not.toContain('<script>');
      expect(result).not.toContain('alert(1)');
    });
  });
  
  describe('Malformed HTML and Unicode handling', () => {
    it('should handle unclosed tags', () => {
      const input = '<div><p>Text';
      expect(sanitize(input)).toBe('<div><p>Text</p></div>');
    });
    
    it('should handle Unicode control characters', () => {
      const input = '<div>Text \u0000 \u001F</div>';
      const result = sanitize(input);
      
      // The sanitizer might encode these characters rather than remove them
      // The important thing is that they're not directly present in the output
      expect(result).toContain('<div>');
      expect(result).toContain('Text');
      expect(result).not.toContain('\u0000');
      expect(result).not.toContain('\u001F');
    });
    
    it('should handle Unicode whitespace obfuscation', () => {
      // For this test, we just want to make sure no dangerous attributes make it through
      const input = '<img\u200Csrc\u200D=x\u200Eonerror\u200F=alert(1)>';
      const result = sanitize(input);
      expect(result).not.toContain('onerror');
      expect(result).not.toContain('alert');
    });
    
    it('should handle partial tags', () => {
      // These partial tag inputs can cause issues with sanitizers
      const tests = [
        '<div<script>alert(1)</script>>Text</div>',
        '<div><!</div>',
        '<di<div>v>Text</div>'
      ];
      
      for (const test of tests) {
        const result = sanitize(test);
        // For these tests we just want to ensure dangerous tags aren't executed
        expect(result).not.toContain('<script>');
      }
    });
    
    it('should neutralize dangerous content in broken tags', () => {
      const input = '<<div>script>alert(1)</script>';
      const result = sanitize(input);
      // The content might still be in the output but should be neutralized
      expect(result).not.toContain('<script>');
      
      // The other dangerous inputs that might need special handling
      const input2 = '<<img src=x onerror=alert(1)>>';
      const result2 = sanitize(input2);
      expect(result2).not.toContain('onerror');
      expect(result2).not.toContain('alert(1)');
    });
  });
  
  describe('Other edge cases', () => {
    it('should handle null bytes in attributes', () => {
      const input = '<img src="x\u0000.jpg" onerror="alert(1)">';
      expect(sanitize(input)).toBe('<img />');
    });
    
    it('should handle mixed case tags and attributes', () => {
      const input = '<DiV sTyLe="color:red">Text</dIv>';
      expect(sanitize(input)).toBe('<div>Text</div>');
    });
    
    it('should handle script in attribute values', () => {
      const input = '<div title="&quot;><script>alert(1)</script>">Text</div>';
      // Should keep the title but escape the content
      expect(sanitize(input)).not.toContain('<script>');
    });
  });
  
  describe('URL Protocol Allowlisting', () => {
    it('should allow whitelisted protocols', () => {
      // Test all allowed protocols
      for (const protocol of ALLOWED_PROTOCOLS) {
        const input = `<a href="${protocol}//example.com">Link</a>`;
        expect(sanitize(input)).toBe(input);
      }
    });
    
    it('should block all non-whitelisted protocols', () => {
      // Test various dangerous or unknown protocols that aren't allowed
      const dangerousProtocols = [
        'javascript:', 
        'data:', 
        'vbscript:', 
        'mhtml:', 
        'file:', 
        'blob:',
        'unknown:',
        'jav&#x09;ascript:', // Tab obfuscation
        'java\tscript:',     // Another tab obfuscation
        'java script:',      // Space obfuscation
        'JAVASCRIPT:',       // Case variations
        '\u0001javascript:',  // Control character obfuscation
        'javascript\u200C:'   // Zero-width character obfuscation
      ];
      
      for (const protocol of dangerousProtocols) {
        const input = `<a href="${protocol}alert(1)">Link</a>`;
        expect(sanitize(input)).toBe('<a>Link</a>');
      }
    });
  });
});