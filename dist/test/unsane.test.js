"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const unsane_1 = require("../src/unsane");
(0, vitest_1.describe)('sanitize', () => {
    (0, vitest_1.it)('should remove disallowed tags', () => {
        const input = '<div>ok<script>alert("bad")</script></div>';
        const output = (0, unsane_1.sanitize)(input, { allowedTags: ['div'] });
        (0, vitest_1.expect)(output).toBe('<div>ok</div>');
    });
    (0, vitest_1.it)('should strip disallowed attributes', () => {
        const input = '<a href="https://example.com" onclick="alert(\'bad\')">Link</a>';
        const output = (0, unsane_1.sanitize)(input, {
            allowedTags: ['a'],
            allowedAttributes: { 'a': ['href'] }
        });
        (0, vitest_1.expect)(output).toContain('href="https://example.com"');
        (0, vitest_1.expect)(output).not.toContain('onclick');
    });
    (0, vitest_1.it)('should properly handle self-closing tags', () => {
        const input = '<div><img src="test.jpg"><br></div>';
        const output = (0, unsane_1.sanitize)(input, {
            allowedTags: ['div', 'img', 'br'],
            allowedAttributes: { 'img': ['src'] },
            selfClosing: true
        });
        (0, vitest_1.expect)(output).toContain('<img src="test.jpg" />');
        (0, vitest_1.expect)(output).toContain('<br />');
    });
    (0, vitest_1.it)('should handle malformed HTML', () => {
        const input = '<div><p>Unclosed paragraph<div>New div</div>';
        const output = (0, unsane_1.sanitize)(input, { allowedTags: ['div', 'p'] });
        // Should close p tag before opening new div
        (0, vitest_1.expect)(output).toBe('<div><p>Unclosed paragraph</p><div>New div</div></div>');
    });
    (0, vitest_1.it)('should use text transform when provided', () => {
        const input = '<p>hello world</p>';
        const output = (0, unsane_1.sanitize)(input, {
            allowedTags: ['p'],
            transformText: (text) => text.toUpperCase()
        });
        (0, vitest_1.expect)(output).toBe('<p>HELLO WORLD</p>');
    });
});
