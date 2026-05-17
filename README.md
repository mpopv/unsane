![Unsane logo](https://github.com/user-attachments/assets/ee83110e-82c1-4514-a8e9-da946096bab9)

# Unsane

A tiny, zero-dependency, run-anywhere HTML sanitization library written in TypeScript.

## Features

- **Lightweight**: ~5.5KB minified runtime import closure, ~2.4KB minified+gzipped
- **Zero dependencies**: Includes internal HTML entity encoder/decoder and state machine tokenizer
- **Run anywhere**: Doesn't rely on DOM APIs, JSDOM, or Node APIs, so you can use in any environment

## Installation

```bash
npm install unsane
```

## Requirements

Unsane requires **Node.js 18.18.0 or later**.

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
  }
};

const dirty =
  '<script>alert("xss")</script><a href="https://example.com" onclick="hack()" style="color:red">Link</a>';
const clean = sanitize(dirty, options);
// -> '<a href="https://example.com">Link</a>'
```

Available options:

- `allowedTags` – array of tag names that are kept in the sanitized output.
- `allowedAttributes` – object mapping tag names to allowed attributes. Use
  `"*"` for attributes allowed on all tags.

URL-bearing attributes use a fixed conservative protocol allowlist:
`http:`, `https:`, `mailto:`, `tel:`, `ftp:`, and `sms:`. Custom protocol
allowlists are intentionally not part of the public API.

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

### CLI Usage

You can also sanitize input directly from the command line:

```bash
echo '<script>alert("xss")</script>' | npx unsane
```

This reads HTML from `stdin` and prints the sanitized result to `stdout`.

## Runtime Size

This library is designed to be lightweight while providing comprehensive HTML sanitization:

| Metric                                 | Size         |
| -------------------------------------- | ------------ |
| Runtime import closure                 | ~24.88 KB    |
| Runtime import closure gzipped         | ~6.34 KB     |
| Minified runtime closure               | ~5.45 KB     |
| **Minified + gzipped runtime closure** | **~2.35 KB** |

You can check the package size yourself with:

```bash
npm run analyze-size
```

## Threat Model

- **Supported contexts**: Designed for server-side rendering pipelines and JavaScript runtimes (Node.js ≥18.18.0, Cloudflare Workers, Deno) where DOM APIs are unavailable. Browser usage is possible, but the sanitizer never mutates DOM nodes directly; it only returns sanitized HTML strings.
- **Supported inputs**: Operates on HTML *fragments* (snippets destined for innerHTML/text interpolation). Full documents (`<!DOCTYPE>`, `<html>`, `<head>`) are normalized but not guaranteed to preserve structure.
- **Guarantees**: Removes elements outside a conservative allowlist, strips disallowed attributes (especially event handlers and URL-bearing attributes with non-HTTP(S)/mailto/tel/ftp/sms protocols), normalizes and escapes inline text, and self-closes void tags.
- **Non-goals / exclusions**: Does **not** sanitize or interpret CSS (`style` attributes are dropped), JavaScript, MathML, or SVG namespaces—content in those namespaces is removed rather than partially sanitized. It does not attempt to sanitize inline `<style>` blocks or external resources (`<link>`, `<script>`, `<iframe>`, etc.) and should be paired with CSPs.
- **Consumer responsibilities**: Validate that customized `allowedTags`/`allowedAttributes` meet your application’s needs, run application-specific allowlist tests, and apply additional sanitization for CSS/URL rewriting if end users can supply styles or alternate protocols.
- **Intended use**: Defense-in-depth for semi-trusted markup (e.g., Markdown already filtered elsewhere). Do not treat Unsane as a drop-in replacement for battle-tested libraries like DOMPurify without additional auditing, fuzzing, and monitoring.

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
