import { describe, expect, it } from "vitest";
import {
  findSkippedContentEnd,
  findTagEnd,
  shouldSkipElementContent,
} from "./rawText.js";

describe("raw-text scanning", () => {
  it("classifies only exact skipped-content element names", () => {
    const skipped =
      "base embed iframe link math meta noembed noframes noscript object script style svg template textarea title xmp".split(
        " ",
      );

    for (const tagName of skipped) {
      expect(shouldSkipElementContent(tagName), tagName).toBe(true);
      expect(shouldSkipElementContent(`${tagName}x`), `${tagName}x`).toBe(
        false,
      );
    }
    expect(shouldSkipElementContent("xscript")).toBe(false);
  });

  it("finds tag ends and uses EOF as the unterminated sentinel", () => {
    expect(findTagEnd("<script>text", 1)).toBe(7);
    expect(findTagEnd("<script", 1)).toBe(6);
  });

  it.each([">", "/>", " >", "\t>", "\n>", "\f>", "\r>"])(
    "accepts a raw-text close followed by %j",
    (suffix) => {
      const html = `<script>hidden</ScRiPt${suffix}<p>safe</p>`;
      const openTagEnd = html.indexOf(">");
      const closeTagEnd = html.indexOf(">", openTagEnd + 1);

      expect(findSkippedContentEnd(html, "script", openTagEnd, 1)).toBe(
        closeTagEnd,
      );
    },
  );

  it("rejects close-tag prefixes and keeps scanning for the exact name", () => {
    const html =
      "<script>hidden</scriptx><p>still hidden</p></script><p>safe</p>";

    expect(findSkippedContentEnd(html, "script", 7, 1)).toBe(
      html.indexOf(">", html.indexOf("</script>")),
    );
  });

  it("handles namespace self-closing syntax without treating HTML raw text as self-closing", () => {
    expect(findSkippedContentEnd("<svg/>tail", "svg", 5, 1)).toBe(5);
    expect(findSkippedContentEnd("<math />tail", "math", 7, 1)).toBe(7);
    expect(findSkippedContentEnd("<script/>tail", "script", 8, 1)).toBe(12);
  });
});
