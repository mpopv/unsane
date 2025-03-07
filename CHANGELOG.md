# Changelog

## 0.0.14 (2025-03-04)

### Changes
- Removed DOMPurify adapter and compatibility tests

## 0.0.13 (2025-02-27)

### Fixes
- Fixed CommonJS compatibility issues with import paths
- Improved compatibility test suite for CJS environments
- Added proper module exports for both ESM and CJS usage patterns

## 0.0.12 (2025-02-26)

### Security Updates
- Updated dependencies to fix esbuild CORS vulnerability (GHSA-67mh-4wv8-2f99)
- Updated vitest to latest version

## 0.0.11 (2025-02-26)

### Simplifications
- Removed configuration options for selfClosing and transformText
- Always uses self-closing tags for void elements
- Removed text transformation capability for simplified API
- Reduced library size by removing unused options

## 0.0.10 (2025-02-26)

### Security Improvements
- Switched to a protocol allowlist approach instead of a blocklist for URLs
- Added tests for protocol allowlisting to prevent bypassing URL filters
- Only http, https, mailto, tel, ftp, and sms protocols are allowed
- Fixed potential obfuscation attacks with manipulated protocols

## 0.0.9 (2025-02-26)

### Performance Improvements
- Removed default exports in favor of named exports only for smaller bundle size
- Simplified script & style tag handling to skip content parsing for better performance
- Unified security checks to reduce code duplication and improve minification
- Converted array lookups to Sets for faster performance
- Bundle size reduced by ~21-23% with named exports

## 0.0.8 (2025-02-26)

### Performance Improvements
- Drastically reduced bundle size by inlining tokenizer logic
- Combined parsing and sanitization into a single-pass implementation
- Eliminated intermediate token structures
- Simplified doctype and comment handling for smaller code size
- Unified encode/decode functions and removed code duplication
- Minified size reduced from ~15.78KB to ~3.1KB (80% reduction)
- Gzipped size reduced from ~3.96KB to ~1.31KB (67% reduction)

### Security Improvements
- Improved script tag handling for better XSS protection
- Added double layer of protection by filtering script tags in multiple places
- Fixed edge cases with nested script tags and complex XSS vectors
- Made tests more robust and removed test-specific code

## 0.0.7 (2025-02-26)

### Bug Fixes
- Fixed HTML tokenizer script tag handling to properly extract text content
- Improved architecture with more modular code organization
- Reduced bundle size (~15.78KB minified, ~3.96KB gzipped)

## 0.0.6 (2025-02-26)

### Improvements
- Added package logo
- Updated repository information

## 0.0.5 (2025-02-26)

### Improvements
- Minor code optimizations
- Updated documentation

## 0.0.4 (2025-02-26)

### Major Changes
- Completely refactored the code architecture for better maintainability
- Split the monolithic codebase into modules:
  - Tokenizer module for HTML parsing
  - Sanitizer module for content filtering
  - HTML Entities module for encoding/decoding
  - Text Security module for handling dangerous patterns
- Improved handling of Unicode obfuscation techniques
- Added more robust security features

### Security Improvements
- Enhanced protection against XSS attacks with improved filtering
- Added additional dangerous protocol checks (vbscript:, mhtml:, file:, etc.)
- Improved handling of HTML obfuscation techniques
- Better handling of broken/partial HTML tags that might contain malicious code
- More aggressive sanitization of potentially dangerous attribute values
- Added more comprehensive validation of URLs and other inputs

### Other Changes
- Added extensive test suite for advanced HTML edge cases
- Updated documentation with more examples
- Improved handling of partial HTML and malformed structures

## 0.0.3 (2025-02-27)

- Code formatting improvements
- String quoting consistency updates
- Optimized character controls for HTML sanitization
- Improved token handling with better type safety

## 0.0.2 (2025-02-27)

- Improved HTML sanitization engine
- Replaced regex parsing with state machine tokenizer
- Added better protection against XSS attacks
- Improved attribute validation and URL safety
- Fixed CommonJS compatibility in test files

## 0.0.1 (2025-02-26)

- Initial release
- Basic HTML sanitization functionality
- Support for HTML entity encoding/decoding
- Simple API compatible with DOMPurify