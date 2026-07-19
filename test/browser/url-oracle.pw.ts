import { expect, test } from "@playwright/test";
import { sanitize } from "../../dist/index.js";

const dangerousProtocols = [
  "javascript",
  "data",
  "vbscript",
  "file",
  "blob",
  "mhtml",
  "filesystem",
] as const;

const allowedProtocols = [
  "http:",
  "https:",
  "mailto:",
  "tel:",
  "ftp:",
  "sms:",
] as const;

const separators = [
  "\t",
  "\n",
  "\r",
  "&#9;",
  "&#10;",
  "&#x09;",
  "&#x0a;",
  "&Tab;",
  "&NewLine;",
  "\u0000",
  "\u200c",
  "\u200d",
  "\ufeff",
] as const;

function dangerousUrlCorpus(): string[] {
  const corpus = new Set<string>();

  for (const protocol of dangerousProtocols) {
    const mixedCase = [...protocol]
      .map((character, index) =>
        index % 2 === 0 ? character.toUpperCase() : character,
      )
      .join("");

    for (const colon of [":", "&#58;", "&#x3a;", "&colon;", "&colon"]) {
      corpus.add(`${protocol}${colon}globalThis.__unsaneExecuted=true`);
      corpus.add(`${mixedCase}${colon}globalThis.__unsaneExecuted=true`);
      corpus.add(
        `${protocol}&amp;${colon.slice(1)}globalThis.__unsaneExecuted=true`,
      );
    }

    for (let index = 1; index < protocol.length; index++) {
      for (const separator of separators) {
        corpus.add(
          `${protocol.slice(0, index)}${separator}${protocol.slice(index)}:globalThis.__unsaneExecuted=true`,
        );
      }
    }
  }

  return [...corpus];
}

const safeUrls = [
  "",
  "/docs",
  "./docs",
  "../docs",
  "docs/page",
  "?query=one&amp;page=2",
  "#fragment",
  "https://example.com/path",
  "HTTP://example.com/path",
  "mailto:security@example.com",
  "tel:+15551234567",
  "ftp://example.com/file",
  "sms:+15551234567",
  "\\relative\\windows-style",
] as const;

test("matches browser URL parsing without accepting unsafe schemes", async ({
  page,
}) => {
  await page.setContent('<!doctype html><base href="https://safe.example/root/">');

  const candidates = dangerousUrlCorpus().map((value) => ({
    value,
    sanitized: sanitize(`<a href="${value}">link</a>`),
  }));

  const result = await page.evaluate(
    ({ protocols, values }) => {
      const unsafeProtocols = new Set(protocols.map((value) => `${value}:`));
      const unsafeAccepted: Array<{
        raw: string;
        rawAttribute: string | null;
        rawProtocol: string;
        sanitized: string;
        sanitizedAttribute: string | null;
      }> = [];
      let browserUnsafe = 0;

      for (const candidate of values) {
        const rawContainer = document.createElement("div");
        rawContainer.innerHTML = `<a href="${candidate.value}">link</a>`;
        const rawAnchor = rawContainer.querySelector("a")!;
        const rawProtocol = rawAnchor.protocol.toLowerCase();

        const sanitizedContainer = document.createElement("div");
        sanitizedContainer.innerHTML = candidate.sanitized;
        const sanitizedAttribute =
          sanitizedContainer.querySelector("a")?.getAttribute("href") ?? null;

        if (unsafeProtocols.has(rawProtocol)) {
          browserUnsafe++;
          if (sanitizedAttribute !== null) {
            unsafeAccepted.push({
              raw: candidate.value,
              rawAttribute: rawAnchor.getAttribute("href"),
              rawProtocol,
              sanitized: candidate.sanitized,
              sanitizedAttribute,
            });
          }
        }
      }

      return { browserUnsafe, unsafeAccepted };
    },
    { protocols: dangerousProtocols, values: candidates },
  );

  expect(result.browserUnsafe).toBeGreaterThan(100);
  expect(result.unsafeAccepted).toEqual([]);
});

test("retains legitimate relative and allowlisted URLs in browser DOMs", async ({
  page,
}) => {
  await page.setContent('<!doctype html><base href="https://safe.example/root/">');

  const candidates = safeUrls.map((value) => ({
    value,
    sanitized: sanitize(`<a href="${value}">link</a>`),
  }));

  const result = await page.evaluate(
    ({ protocols, values }) => {
      const allowed = new Set(protocols);

      return values.map((candidate) => {
        const container = document.createElement("div");
        container.innerHTML = candidate.sanitized;
        const anchor = container.querySelector("a")!;

        return {
          raw: candidate.value,
          retained: anchor.hasAttribute("href"),
          resolvedProtocol: anchor.protocol.toLowerCase(),
          protocolAllowed: allowed.has(anchor.protocol.toLowerCase()),
        };
      });
    },
    { protocols: allowedProtocols, values: candidates },
  );

  expect(result).toEqual(
    result.map((candidate) => ({
      ...candidate,
      retained: true,
      protocolAllowed: true,
    })),
  );
});
