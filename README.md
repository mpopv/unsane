# unsane

A strict, TypeScript-based HTML sanitization library, inspired by insane.

## Features

- Whitelist-based HTML sanitizer
- Stack-based parser for robust handling of malformed HTML
- Strict TypeScript types
- Optional text transforms and attribute filtering
- Handles self-closing tags properly
- Zero dependencies - includes its own HTML entity encoding/decoding

## Installation

```bash
npm install unsane
```

## Usage

```ts
import { sanitize } from 'unsane';

// Basic usage with default settings
const safeHtml = sanitize('<div>Good <script>alert("bad")</script></div>');
// => <div>Good </div>

// Custom allowed tags and attributes
const customSafeHtml = sanitize('<a href="https://example.com" onclick="alert()">Link</a>', {
  allowedTags: ['a'],
  allowedAttributes: {
    'a': ['href']
  }
});
// => <a href="https://example.com">Link</a>

// Text transformation
const transformedHtml = sanitize('<p>hello world</p>', {
  allowedTags: ['p'],
  transformText: (text) => text.toUpperCase()
});
// => <p>HELLO WORLD</p>
```

## API

### sanitize(html, options?)

Sanitizes HTML by removing disallowed tags and attributes.

#### Parameters

- `html` - The HTML string to sanitize
- `options` - Optional configuration object:
  - `allowedTags` - Array of allowed HTML tag names (default includes common safe tags)
  - `allowedAttributes` - Object mapping tag names to arrays of allowed attribute names
  - `selfClosing` - Boolean controlling if self-closing tags should have a slash (default: true)
  - `transformText` - Optional function to transform text content

#### Returns

A sanitized HTML string.

## Contributing

1. Fork & clone this repo
2. Create a feature branch
3. Implement / fix / test
4. Create a pull request

## License

[MIT](./LICENSE)