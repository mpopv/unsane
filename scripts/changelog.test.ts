import { describe, expect, it } from "vitest";
import { extractUnreleased, rollUnreleased } from "./changelog.js";

const changelog = `# Changelog

## Unreleased

### Fixes

- Fixed the thing.

## 0.0.1 (2025-01-01)

- Initial release.
`;

describe("changelog release helpers", () => {
  it("extracts release notes without an existing version heading", () => {
    expect(extractUnreleased(changelog)).toBe(
      "### Fixes\n\n- Fixed the thing.",
    );
  });

  it("rolls Unreleased notes into a dated version section", () => {
    expect(rollUnreleased(changelog, "0.1.0", "2026-08-03")).toBe(`# Changelog

## Unreleased

## 0.1.0 (2026-08-03)

### Fixes

- Fixed the thing.

## 0.0.1 (2025-01-01)

- Initial release.
`);
  });

  it("rejects missing notes, malformed versions, and duplicate versions", () => {
    expect(() => extractUnreleased("## Unreleased\n\n")).toThrow(
      "No Unreleased changelog notes found.",
    );
    expect(() => rollUnreleased(changelog, "next", "2026-08-03")).toThrow(
      "Invalid release version: next",
    );
    expect(() => rollUnreleased(changelog, "0.1.0", "August 3")).toThrow(
      "Invalid release date: August 3",
    );
    expect(() => rollUnreleased(changelog, "0.0.1", "2026-08-03")).toThrow(
      "CHANGELOG.md already contains version 0.0.1.",
    );
    expect(() =>
      rollUnreleased(
        `${changelog}\n## v0.1.0-beta.1\n`,
        "0.1.0-beta.1",
        "2026-08-03",
      ),
    ).toThrow("CHANGELOG.md already contains version 0.1.0-beta.1.");
    expect(() => extractUnreleased("# Changelog\n")).toThrow(
      "CHANGELOG.md is missing an Unreleased section.",
    );
  });
});
