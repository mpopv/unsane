const SKIPPED_CONTENT = new Set(
  "base embed iframe link math meta noembed noframes noscript object plaintext script style svg template textarea title xmp".split(
    " ",
  ),
);

export function shouldSkipElementContent(tagName: string): boolean {
  return SKIPPED_CONTENT.has(tagName);
}

export function findTagEnd(html: string, position: number): number {
  const tagEnd = html.indexOf(">", position);
  return tagEnd === -1 ? html.length - 1 : tagEnd;
}

export function findSkippedContentEnd(
  html: string,
  tagName: string,
  openTagEnd: number,
  tagStart: number,
): number {
  // Browsers never leave the PLAINTEXT state, so it swallows the rest.
  if (tagName === "plaintext") return html.length - 1;

  if (
    (tagName === "svg" || tagName === "math") &&
    html.slice(tagStart, openTagEnd).trimEnd().endsWith("/")
  ) {
    return openTagEnd;
  }

  let closeTagStart = html.indexOf("</", openTagEnd + 1);
  while (closeTagStart >= 0) {
    const nameStart = closeTagStart + 2;
    const candidate = html.slice(nameStart, nameStart + tagName.length);
    const boundary = html[nameStart + tagName.length];
    if (candidate.toLowerCase() === tagName && /[\s/>]/.test(boundary)) {
      return findTagEnd(html, nameStart + tagName.length);
    }

    closeTagStart = html.indexOf("</", nameStart);
  }

  return html.length - 1;
}
