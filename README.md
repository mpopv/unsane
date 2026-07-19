![Unsane logo](https://github.com/user-attachments/assets/ee83110e-82c1-4514-a8e9-da946096bab9)

# Unsane

A tiny, zero-dependency, run-anywhere HTML sanitization library written in TypeScript.

## Features

- **Lightweight**: ~8.9KB minified runtime import closure, ~3.5KB minified+gzipped
- **Zero dependencies**: Includes internal HTML entity encoder/decoder and state machine tokenizer
- **Run anywhere**: Doesn't rely on DOM APIs, JSDOM, or Node APIs, so you can use in any environment

## Installation

```bash
npm install unsane
```

## Requirements

Unsane requires a supported release of **Node.js 22 or later**.

## Usage

### Basic Usage

```javascript
// ES Modules
import { sanitize } from "unsane";

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

When the same policy is used repeatedly, compile it once to avoid rebuilding
its lookup tables for every input:

```javascript
import { createSanitizer } from "unsane";

const comments = createSanitizer({
  allowedTags: ["p", "strong", "em", "a"],
  allowedAttributes: { a: ["href"] },
});

comments('<p><a href="/docs">Read the docs</a></p>');
```

Available options:

- `allowedTags` – array of tag names that are kept in the sanitized output.
- `allowedAttributes` – object mapping tag names to allowed attributes. Use
  `"*"` for attributes allowed on all tags.
- `maxInputLength` – maximum input string length accepted by `sanitize()`.
  Defaults to `1_000_000` characters. Set to `Infinity` only for trusted,
  already-bounded inputs.

Custom allowlists cannot re-enable document-active elements (`base`, `link`, or
`meta`) or active attributes that require a separate parser (`is`, `ping`,
`srcdoc`, `srcset`, and `imagesrcset`). Unsane strips these capabilities even
when explicitly listed. Inert custom elements, `data-*`, and `aria-*`
attributes remain supported.

URL-bearing attributes use a fixed conservative protocol allowlist:
`http:`, `https:`, `mailto:`, `tel:`, `ftp:`, and `sms:`. Custom protocol
allowlists are intentionally not part of the public API. Relative URLs and
fragments are allowed, while protocol-relative URLs (`//example.com`) are
removed.

Links with `target="_blank"` are emitted with `rel="noopener noreferrer"` even
when `rel` is omitted from a custom allowlist.

### Security Notes

- Unsane sanitizes HTML fragments, not full document policies. Keep Content
  Security Policy, Trusted Types, and framework escaping in place.
- URL attributes are checked after entity decoding and protocol normalization,
  but URL rewriting and link reputation checks remain the caller's job.
- Inputs longer than the configured `maxInputLength` throw a `RangeError`; keep
  upstream request-body limits in place for untrusted traffic.
- CSS is not sanitized. `style` attributes and `<style>` elements are dropped
  instead of parsed.
- SVG and MathML are outside the supported safe subset and are removed rather
  than partially sanitized.
- If you expand the tag or attribute allowlists, add app-specific tests for the
  markup you now accept.

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

This library is designed to be lightweight while providing comprehensive HTML sanitization. The size gate builds the actual tree-shaken consumer entry point and checks the package that npm would publish:

| Metric                       | Size              |
| ---------------------------- | ----------------- |
| Minified consumer ESM bundle | ~6.82 KB          |
| Minified + gzip              | ~2.98 KB          |
| Minified + Brotli            | ~2.73 KB          |
| npm tarball / unpacked size  | ~15.72 / 82.99 KB |

You can check the package size yourself with:

```bash
npm run analyze-size
```

This command enforces conservative bundle and published-package budgets in CI
so accidental growth fails before release. Runtime throughput can be measured
against representative plain-text, safe-fragment, attribute-heavy, raw-content,
and hostile-nesting workloads with:

```bash
npm run build
npm run benchmark
```

## Threat Model

- **Supported contexts**: Designed for server-side rendering pipelines and JavaScript runtimes (Node.js ≥22, Cloudflare Workers, Deno) where DOM APIs are unavailable. Browser usage is possible, but the sanitizer never mutates DOM nodes directly; it only returns sanitized HTML strings.
- **Supported inputs**: Operates on HTML _fragments_ (snippets destined for innerHTML/text interpolation). Full documents (`<!DOCTYPE>`, `<html>`, `<head>`) are normalized but not guaranteed to preserve structure.
- **Guarantees**: Removes elements outside a conservative allowlist, strips disallowed attributes (especially event handlers, protocol-relative URLs, and URL-bearing attributes with non-HTTP(S)/mailto/tel/ftp/sms protocols), normalizes and escapes inline text, and self-closes void tags.
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
