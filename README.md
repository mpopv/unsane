![Unsane logo](https://github.com/user-attachments/assets/ee83110e-82c1-4514-a8e9-da946096bab9)

# Unsane

A tiny, zero-dependency, run-anywhere HTML sanitization library written in TypeScript.

## Features

- **Lightweight**: ~3.2KB minified, ~1.4KB minified+gzipped
- **Zero dependencies**: Includes internal HTML entity encoder/decoder and state machine tokenizer
- **Run anywhere**: Doesn't rely on DOM APIs, JSDOM, or Node APIs, so you can use in any environment

## Installation

```bash
npm install unsane
```

## Usage

### Basic Usage

```javascript
// ES Modules
import { sanitize } from "unsane";

// CommonJS
const { sanitize } = require("unsane");

// Input: potentially malicious HTML
const dirty =
  '<script>alert("xss")</script><div onclick="alert(`pwned`)">Hello</div>';

// Output: clean HTML with dangerous elements/attributes removed
const clean = sanitize(dirty);
// -> '<div>Hello</div>'
```

### Configuration Options

You can customize the sanitizer behavior with options:

```javascript
import { sanitize } from "unsane";

const options = {
  // Custom list of allowed tags
  allowedTags: ["p", "span", "strong", "em", "a", "img"],

  // Custom list of allowed attributes for each tag
  allowedAttributes: {
    a: ["href", "target"],
    img: ["src", "alt", "width", "height"],
    "*": ["id", "class"], // Attributes allowed on all elements
  },
};

const dirty =
  '<script>alert("xss")</script><a href="https://example.com" onclick="hack()" style="color:red">Link</a>';
const clean = sanitize(dirty, options);
// -> '<a href="https://example.com">Link</a>'
```

### HTML Entity Functions

```javascript
import { encode, decode, escape } from "unsane";

// Encode special characters into entities
const encoded = encode('<div>"text"</div>');
// -> '&#x3C;div&#x3E;&#x22;text&#x22;&#x3C;/div&#x3E;'

// Decode HTML entities
const decoded = decode("&lt;div&gt;&quot;text&quot;&lt;/div&gt;");
// -> '<div>"text"</div>'

// Escape HTML special characters
const escaped = escape('<script>"alert"</script>');
// -> '&lt;script&gt;&quot;alert&quot;&lt;/script&gt;'
```

## Bundle Size

This library is designed to be lightweight while providing comprehensive HTML sanitization:

| Metric                 | Size         |
| ---------------------- | ------------ |
| Unpacked               | ~15.69 KB    |
| Minified               | ~3.1 KB      |
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

## Browser Compatibility

Works in all modern browsers as well as Node.js environments. No DOM or browser APIs are required.

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on setting up the project and running tests. The `dist` directory is generated and should not be committed.


## License

MIT

