import { expect, test } from "@playwright/test";
import { sanitize } from "../../dist/index.js";

const insertionContexts = ["div", "table", "select", "template"] as const;

const mutationXssCorpus = [
  {
    name: "event handler image",
    html: '<img src="x" onerror="globalThis.__unsaneExecuted = true">',
  },
  {
    name: "entity-obfuscated protocol",
    html: '<a href="java&#x0A;script:globalThis.__unsaneExecuted=true">link</a>',
  },
  {
    name: "data URL image",
    html: '<img src="data:text/html,<script>globalThis.__unsaneExecuted=true</script>">',
  },
  {
    name: "foreign content breakout",
    html: '<svg><foreignObject><p><img src="x" onerror="globalThis.__unsaneExecuted=true"></p></foreignObject></svg><p>safe</p>',
  },
  {
    name: "math style mutation",
    html: '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=globalThis.__unsaneExecuted=true>">',
  },
  {
    name: "noscript raw text confusion",
    html: '<noscript><p title="</noscript><img src=x onerror=globalThis.__unsaneExecuted=true>">text</p></noscript><p>safe</p>',
  },
  {
    name: "textarea breakout",
    html: '<textarea></textarea><img src=x onerror="globalThis.__unsaneExecuted=true">',
  },
  {
    name: "template content",
    html: '<template><img src=x onerror="globalThis.__unsaneExecuted=true"></template><p>safe</p>',
  },
  {
    name: "malformed nested script",
    html: "<div><scr<script>ipt>globalThis.__unsaneExecuted=true</script><span>safe</span></div>",
  },
  {
    name: "table foreign content",
    html: '<table><tr><td><svg><script>globalThis.__unsaneExecuted=true</script></svg><img src=x onerror="globalThis.__unsaneExecuted=true"></td></tr></table>',
  },
] as const;

test.beforeEach(async ({ page }) => {
  await page.setContent("<!doctype html><body></body>");
  await page.evaluate(() => {
    Object.assign(globalThis, { __unsaneExecuted: false });
  });
});

for (const payload of mutationXssCorpus) {
  test(`stays inert after reparsing ${payload.name}`, async ({ page }) => {
    const sanitized = sanitize(payload.html);
    const dialogs: string[] = [];

    page.on("dialog", async (dialog) => {
      dialogs.push(dialog.message());
      await dialog.dismiss();
    });

    for (const context of insertionContexts) {
      const result = await page.evaluate(
        ({ contextName, html }) => {
          const container = document.createElement(contextName);
          document.body.replaceChildren(container);
          container.innerHTML = html;

          const root =
            container instanceof HTMLTemplateElement
              ? container.content
              : container;
          const forbiddenElements = Array.from(
            root.querySelectorAll(
              "script, style, iframe, object, embed, svg, math, base, link, meta",
            ),
            (element) => element.localName,
          );
          const forbiddenAttributes: string[] = [];
          const unsafeUrls: string[] = [];

          for (const element of root.querySelectorAll("*")) {
            for (const attribute of element.attributes) {
              if (
                /^(?:on|style$|action$|formaction$|xlink:href$|srcdoc$|srcset$|imagesrcset$|ping$|is$)/i.test(
                  attribute.name,
                )
              ) {
                forbiddenAttributes.push(
                  `${element.localName}[${attribute.name}]`,
                );
              }

              if (
                /^(?:href|src|cite|poster)$/i.test(attribute.name) &&
                /^\s*(?:javascript|data|vbscript|file|blob|mhtml|filesystem):/i.test(
                  attribute.value,
                )
              ) {
                unsafeUrls.push(
                  `${element.localName}[${attribute.name}=${attribute.value}]`,
                );
              }
            }
          }

          return {
            executed: Boolean(
              (globalThis as typeof globalThis & {
                __unsaneExecuted?: boolean;
              }).__unsaneExecuted,
            ),
            forbiddenAttributes,
            forbiddenElements,
            unsafeUrls,
          };
        },
        { contextName: context, html: sanitized },
      );

      expect(result.forbiddenElements, `${payload.name} in ${context}`).toEqual(
        [],
      );
      expect(
        result.forbiddenAttributes,
        `${payload.name} in ${context}`,
      ).toEqual([]);
      expect(result.unsafeUrls, `${payload.name} in ${context}`).toEqual([]);
      expect(result.executed, `${payload.name} in ${context}`).toBe(false);
    }

    expect(dialogs, payload.name).toEqual([]);
  });
}

test("preserves a canonical benign fragment", async ({ page }) => {
  const sanitized = sanitize(
    '<p id="intro">Hello <strong>world</strong> <a href="/docs" target="_blank">Docs</a></p>',
  );

  const browserHtml = await page.evaluate((html) => {
    const container = document.createElement("div");
    container.innerHTML = html;
    return container.innerHTML;
  }, sanitized);

  expect(browserHtml).toBe(
    '<p id="intro">Hello <strong>world</strong> <a href="/docs" target="_blank" rel="noopener noreferrer">Docs</a></p>',
  );
});
