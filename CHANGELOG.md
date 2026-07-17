# Changelog

## Unreleased

### Breaking Changes

- Removed the CommonJS build and `require` export; Unsane is now an ESM-only package for Node.js 22 and later.

### Fixes

- Added safe `rel="noopener noreferrer"` hardening for links emitted with `target="_blank"`.
- Added configurable input-length guardrails through `maxInputLength`.
- Hardened URL attribute filtering by decoding entity-obfuscated protocols, blocking protocol-relative URLs, and avoiding generic text heuristics for otherwise safe URLs.
- Preserved explicit empty attribute values separately from boolean attributes.
- Normalized custom sanitizer tag and attribute allowlists to lowercase before matching.
- Fixed CLI execution on Node 18 by using a `.js` bin target while preserving the `unsane` command name.
- Fixed size analysis to inspect the current `dist/` runtime import closure instead of stale `dist/src/` paths.
- Clarified that URL protocols are intentionally fixed to Unsane's conservative allowlist rather than configurable through an `allowedProtocols` option.
- Raised the documented Node.js support floor to `>=22`, matching supported upstream release lines and CI coverage.

### Improvements

- Fused URL entity decoding, control detection, and whitespace removal, and combined text control filtering with escaping to avoid repeated full-input scans.
- Reduced sanitizer allocation by slicing text and attribute values from the source only when each token closes, with a direct plain-text path that bypasses markup parsing.
- Precompiled the default sanitizer policy and added `createSanitizer()` for callers that reuse custom policies across many inputs.
- Added changelog-derived release notes, `npm publish --dry-run`, and post-release npm artifact verification to the release flow.
- Pinned GitHub Actions by commit, bounded workflow concurrency/runtime, enforced release tag/version equality, and wired registry verification into publishing.
- Added performance regression coverage for large fragments, deep nesting, and large attribute payloads.
- Expanded malformed parser coverage with browser-reparse invariants.
- Renamed older coverage-oriented tests around observable sanitizer behavior.
- Refreshed development dependencies to clear the npm audit report while keeping the Vite/Vitest toolchain on the Node 18-compatible line.
- Made `npm run build` clean `dist/` before compiling so stale generated files cannot leak into package checks.
- Added exact packed-file assertions and TypeScript consumer validation to the package smoke test.
- Added a release-triggered npm publish workflow for trusted publishing / OIDC and hardened the local release script around the full verification gate.
- Added dependency review and runtime size budget enforcement, while keeping the repository compatible with GitHub's CodeQL default setup.
- Strengthened CI to run lint, tests, build, size analysis, package dry-run checks, and package-consumption smoke tests on supported development Node versions.
- Added a corpus-style security regression suite for executable-output invariants.
- Added deterministic generated-input sanitizer fuzz coverage.
- Broadened differential sanitizer checks to assert hostile-input invariants against DOMPurify and `sanitize-html`.
- Simplified inert text handling to decode and escape text directly without a misleading dangerous-word pass.

## 0.0.19 (2025-10-22)

### Security Improvements

- Added OWASP-vector sanitizer coverage and differential checks against DOMPurify and `sanitize-html`.
- Migrated ESLint configuration to flat config and refreshed security documentation.
- Hardened malformed-markup handling in sanitizer tests and implementation.

## 0.0.18 (2025-10-22)

### Fixes

- Fixed CI and lint compatibility with the current ESLint dependency stack.

## 0.0.17 (2025-10-22)

### Changes

- Release metadata update only.

## 0.0.16 (2025-10-22)

### Changes

- Release metadata update only.

## 0.0.15 (2025-10-22)

### Improvements

- Added Node.js engine metadata and documented the Node.js requirement.
- Added the `unsane` CLI for stdin-to-stdout sanitization.
- Added npm package file controls and stopped tracking generated `dist/` output.
- Added initial GitHub Actions CI coverage for linting and tests.
- Fixed CommonJS build output paths and release build compatibility.

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
