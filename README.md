![Unsane logo](https://github.com/user-attachments/assets/ee83110e-82c1-4514-a8e9-da946096bab9)

# unsane

A tiny, zero-dependency, run-anywhere HTML sanitization library written in TypeScript.

## Features

- **Tiny drop-in replacement for DOMPurify**: Tested against DOMPurify's own tests with improved XSS protection.
- **Pure TypeScript**: doesn't rely on DOM APIs, JSDOM, or Node APIs, so you can use in any environment.
- **Zero dependencies**: includes its own HTML entity encoding/decoding
- **Robust HTML parsing**: uses a state machine tokenizer for accurate HTML parsing
- **Ultra-lightweight**: ~16KB unpacked, ~4KB minified+gzipped

## Installation

```bash
npm install unsane
```

## Usage

```ts
import { sanitize } from "unsane";

// Basic usage with default settings
const safeHtml = sanitize('<div>Good <script>alert("bad")</script></div>');
// => <div>Good </div>

// Custom allowed tags and attributes
const customSafeHtml = sanitize(
  '<a href="https://example.com" onclick="alert()">Link</a>',
  {
    allowedTags: ["a"],
    allowedAttributes: {
      a: ["href"],
    },
  }
);
// => <a href="https://example.com">Link</a>

// Auto-filters dangerous URLs and event handlers
const xssSafeHtml = sanitize(
  '<a href="javascript:alert(1)">XSS</a><img src="x" onerror="alert(2)">'
);
// => <a>XSS</a><img src="x" />

// Text transformation
const transformedHtml = sanitize("<p>hello world</p>", {
  allowedTags: ["p"],
  transformText: (text) => text.toUpperCase(),
});
// => <p>HELLO WORLD</p>
```

## API

### sanitize(html, options?)

Sanitizes HTML by removing disallowed tags and attributes, with built-in XSS protection.

#### Parameters

- `html` - The HTML string to sanitize
- `options` - Optional configuration object:
  - `allowedTags` - Array of allowed HTML tag names (default includes common safe tags)
  - `allowedAttributes` - Object mapping tag names to arrays of allowed attribute names
  - `selfClosing` - Boolean controlling if self-closing tags should have a slash (default: true)
  - `transformText` - Optional function to transform text content

#### Returns

A sanitized HTML string with:

- Disallowed tags completely removed
- Dangerous attributes filtered out
- JavaScript URLs blocked
- Event handlers removed
- HTML entities properly handled
- Malformed HTML fixed

### Additional Exports

- `decode` - Decode HTML entities to their character representations
- `encode` - Encode characters to HTML entities
- `escape` - Minimal escaping of characters that have special meaning in HTML

### DOMPurify Compatibility

The library includes a compatibility layer for easier migration from DOMPurify:

```ts
import { UnsanePurify } from "unsane/compat";

// Similar API to DOMPurify
const DOMPurify = UnsanePurify();
const clean = DOMPurify.sanitize('<script>alert("xss")</script>');
// => ""
```

## Package Size

This library is designed to be lightweight while providing comprehensive HTML sanitization:

| Metric                 | Size         |
| ---------------------- | ------------ |
| Unpacked               | ~38.3 KB     |
| Minified               | ~16.03 KB    |
| **Minified + Gzipped** | **~4 KB**    |

You can check the package size yourself with:

```bash
npm run analyze-size
```

## Scripts

| Script                 | Description                           |
| ---------------------- | ------------------------------------- |
| `npm run build`        | Builds both ESM and CommonJS versions |
| `npm run test`         | Runs all tests                        |
| `npm run test:ui`      | Runs tests with the Vitest UI         |
| `npm run lint`         | Runs ESLint on all source files       |
| `npm run analyze-size` | Analyzes the bundle size              |
| `npm run clean`        | Removes the dist directory            |

## XSS Protection

Unsane is designed to protect against common XSS vectors:

- Removes all script tags and other dangerous elements
- Filters `javascript:` and `data:` URLs from attributes
- Removes all event handlers (`onclick`, etc.)
- Handles unicode escape sequences in URLs
- Properly encodes HTML entities
- Maintains HTML structure to prevent invalid nesting exploits
- Properly handles HTML edge cases with state machine-based parsing
- Robust handling of attribute values with proper quote parsing

## Compatibility Tests

Unsane implements a subset of DOMPurify's API and passes the most important security-focused test cases:

```bash
node compat-test/compatibility-test.js
```

## Contributing

1. Fork & clone this repo
2. Create a feature branch
3. Implement / fix / test
4. Create a pull request

## License

[MIT](./LICENSE)
