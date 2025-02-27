![Unsane logo](https://github.com/user-attachments/assets/ee83110e-82c1-4514-a8e9-da946096bab9)

# Unsane

A tiny, zero-dependency, run-anywhere HTML sanitization library written in TypeScript.

## Features

- **Lightweight**: ~3.2KB minified, ~1.4KB minified+gzipped
- **Zero dependencies**: Includes internal HTML entity encoder and state machine tokenizer
- **Run anywhere**: Doesn't rely on DOM APIs, JSDOM, or Node APIs, so you can use in any environment
- **Tiny drop-in replacement for DOMPurify**: Tested against DOMPurify's own tests with improved XSS protection

## Installation

```bash
npm install unsane
```

## Usage

### Basic Usage

```javascript
// ES Modules
import { sanitize } from 'unsane';

// CommonJS
// const { sanitize } = require('unsane');

// Input: potentially malicious HTML
const dirty = '<script>alert("xss")</script><div onclick="alert(`pwned`)">Hello</div>';

// Output: clean HTML with dangerous elements/attributes removed
const clean = sanitize(dirty);
// -> '<div>Hello</div>'
```

### Configuration Options

You can customize the sanitizer behavior with options:

```javascript
import { sanitize } from 'unsane';

const options = {
  // Custom list of allowed tags
  allowedTags: ['p', 'span', 'strong', 'em', 'a', 'img'],
  
  // Custom list of allowed attributes for each tag
  allowedAttributes: {
    'a': ['href', 'target'],
    'img': ['src', 'alt', 'width', 'height'],
    // Use '*' for attributes allowed on all elements
    '*': ['id', 'class']
  },
  
  // Self-closing tags like <img /> are always rendered with trailing slash
};

const dirty = '<script>alert("xss")</script><a href="https://example.com" onclick="hack()" style="color:red">Link</a>';
const clean = sanitize(dirty, options);
// -> '<a href="https://example.com">Link</a>'
```

### HTML Entity Functions

```javascript
import { encode, decode, escape } from 'unsane';

// Encode special characters into entities
const encoded = encode('<div>"text"</div>');
// -> '&#x3C;div&#x3E;&#x22;text&#x22;&#x3C;/div&#x3E;'

// Decode HTML entities
const decoded = decode('&lt;div&gt;&quot;text&quot;&lt;/div&gt;');
// -> '<div>"text"</div>'

// Escape HTML special characters
const escaped = escape('<script>"alert"</script>');
// -> '&lt;script&gt;&quot;alert&quot;&lt;/script&gt;'
```

### DOMPurify Compatibility

This package is tested against DOMPurify's test suite to ensure it handles the same XSS vectors:

```javascript
import { sanitize } from 'unsane';

// Handles the same XSS vectors as DOMPurify
const clean = sanitize('<script>alert("xss")</script>');
// -> ''
```

## Bundle Size

This library is designed to be lightweight while providing comprehensive HTML sanitization:

| Metric                 | Size      |
| ---------------------- | --------- |
| Unpacked               | ~15.69 KB |
| Minified               | ~3.1 KB |
| **Minified + Gzipped** | **~1.31 KB** |

You can check the package size yourself with:

```bash
npm run analyze-size
```

## Security Features

Unsane is designed to protect against common XSS vectors:

- Removes dangerous tags like `<script>`, `<style>`, `<iframe>`, etc.
- Strips event handler attributes (`onclick`, `onerror`, etc.)
- Removes `javascript:` URLs and other dangerous protocols
- Handles unicode escape sequences in URLs
- Properly encodes HTML entities
- Maintains HTML structure to prevent invalid nesting exploits
- Properly handles HTML edge cases with state machine-based parsing
- Robust handling of attribute values with proper quote parsing

## Compatibility Tests

This library includes compatibility tests that compare its behavior with DOMPurify's to ensure similar coverage against XSS vectors. Run these with:

```bash
node compat-test/test-runner.js
```

## Browser Compatibility

Works in all modern browsers as well as Node.js environments. No DOM or browser APIs are required.

## License

MIT