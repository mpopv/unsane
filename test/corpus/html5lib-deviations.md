# html5lib tokenizer corpus scope

Unsane runs a pinned, hermetic subset of the upstream
[`html5lib-tests`](https://github.com/html5lib/html5lib-tests) tokenizer corpus.
The generated snapshot records the exact upstream commit, source file, test
description, input, and reference token stream. Refresh it with:

```sh
npm run test:update-html5lib
```

The adapter compares browser DOM fragments produced from upstream tokenizer
tokens with browser DOM fragments produced from Unsane's sanitized output. It
is intentionally limited to cases that match Unsane's contract:

- the default HTML data state, because Unsane accepts complete fragments rather
  than exposing tokenizer-state entry points;
- HTML fragment tokens, excluding SVG, MathML, CDATA, and full-document tree
  construction;
- inert test attributes, because active capabilities have separate security
  oracles and cannot be enabled by a custom policy;
- names accepted by Unsane's compact tag/attribute grammar. Upstream cases that
  create names containing `<` or `=`, reinterpret a slash before attributes, or
  emit a bare `</` text token are conservative preservation deviations rather
  than security gaps and are not selected;
- tokenizer behavior, not parse-error diagnostics, source locations, or exact
  serialization spelling.

Cases outside this scope remain covered by the browser mutation-XSS matrix,
the adversarial generator, and focused security regressions. Any future
security-relevant mismatch found while expanding this snapshot must first be
minimized into the permanent regression corpus, then added here once fixed.
