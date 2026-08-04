const UNRELEASED_HEADER = /^## Unreleased[\t ]*\r?$/m;

interface UnreleasedSection {
  headerStart: number;
  contentStart: number;
  contentEnd: number;
  notes: string;
}

function unreleasedSection(changelog: string): UnreleasedSection {
  const match = UNRELEASED_HEADER.exec(changelog);
  if (!match) throw new Error("CHANGELOG.md is missing an Unreleased section.");

  const contentStart = match.index + match[0].length;
  const nextHeaderOffset = changelog.slice(contentStart).search(/^## /m);
  const contentEnd =
    nextHeaderOffset === -1
      ? changelog.length
      : contentStart + nextHeaderOffset;
  const notes = changelog.slice(contentStart, contentEnd).trim();

  if (!notes) throw new Error("No Unreleased changelog notes found.");

  return { headerStart: match.index, contentStart, contentEnd, notes };
}

export function extractUnreleased(changelog: string): string {
  return unreleasedSection(changelog).notes;
}

export function rollUnreleased(
  changelog: string,
  version: string,
  date: string,
): string {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`Invalid release version: ${version}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw new Error(`Invalid release date: ${date}`);
  }
  if (
    new RegExp(`^## v?${version.replace(/\./g, "\\.")}(?: |$)`, "m").test(
      changelog,
    )
  ) {
    throw new Error(`CHANGELOG.md already contains version ${version}.`);
  }

  const section = unreleasedSection(changelog);
  const before = changelog.slice(0, section.headerStart);
  const after = changelog.slice(section.contentEnd).trim();
  const released = `## ${version} (${date})\n\n${section.notes}`;

  return `${before}## Unreleased\n\n${released}${after ? `\n\n${after}` : ""}\n`;
}
