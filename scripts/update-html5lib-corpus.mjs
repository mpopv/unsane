import { writeFile } from "node:fs/promises";

const UPSTREAM_COMMIT = "224991ec10db04f056a89eed8b0bd8695fd2950e";
const OUTPUT = new URL("../test/corpus/html5lib-applicable.json", import.meta.url);

const selectedDescriptions = {
  "test1.test": [
    "Correct Doctype lowercase",
    "Correct Doctype uppercase",
    "Correct Doctype mixed case",
    "Truncated doctype start",
    "Single Start Tag",
    "Empty end tag",
    "Empty start tag",
    "Start Tag w/attribute",
    "Start Tag w/attribute no quotes",
    "Start/End Tag",
    "End Tag w/attribute",
    "Multiple atts",
    "Multiple atts no space",
    "Repeated attr",
    "Simple comment",
    "Comment, Central dash no space",
    "Comment, two central dashes",
    "Unfinished comment",
    "Start of a comment",
    "Short comment",
    "Short comment two",
    "Short comment three",
    "< in comment",
    "Nested comment",
  ],
  "test2.test": [
    "Entity without a name",
    "Unescaped ampersand in attribute value",
    "Non-void element containing trailing /",
    "Void element with permitted slash",
    "Void element with permitted slash (with attribute)",
    "Double-quoted attribute value",
  ],
  "test4.test": [
    "< in unquoted attribute value",
    "= in unquoted attribute value",
    "Text after bogus character reference",
    "Text after hex character reference",
    "Double-quoted attribute value not followed by whitespace",
    "Single-quoted attribute value not followed by whitespace",
    "Quoted attribute followed by permitted /",
    "Quoted attribute followed by non-permitted /",
  ],
  "entities.test": [
    "Undefined named entity in a double-quoted attribute value ending in semicolon and whose name starts with a known entity name.",
    "Entity name requiring semicolon instead followed by the equals sign in a double-quoted attribute value.",
    "Valid entity name followed by the equals sign in a double-quoted attribute value.",
    "Undefined named entity in an unquoted attribute value ending in semicolon and whose name starts with a known entity name.",
    "Ambiguous ampersand.",
  ],
};

const cases = [];

for (const [file, descriptions] of Object.entries(selectedDescriptions)) {
  const url = `https://raw.githubusercontent.com/html5lib/html5lib-tests/${UPSTREAM_COMMIT}/tokenizer/${file}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Unable to fetch ${url}: ${response.status}`);
  const upstream = await response.json();
  const byDescription = new Map(
    upstream.tests.map((test) => [test.description, test]),
  );

  for (const description of descriptions) {
    const test = byDescription.get(description);
    if (!test) throw new Error(`Missing ${file}: ${description}`);
    if (test.initialStates || test.doubleEscaped) {
      throw new Error(`Selected non-data-state case ${file}: ${description}`);
    }

    cases.push({
      file,
      description,
      input: test.input,
      output: test.output,
    });
  }
}

await writeFile(
  OUTPUT,
  `${JSON.stringify(
    {
      upstream: {
        repository: "https://github.com/html5lib/html5lib-tests",
        commit: UPSTREAM_COMMIT,
      },
      cases,
    },
    null,
    2,
  )}\n`,
);

console.log(`Wrote ${cases.length} pinned html5lib tokenizer cases.`);
