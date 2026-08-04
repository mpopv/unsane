#!/usr/bin/env tsx
import { readFileSync } from "node:fs";
import { extractUnreleased } from "./changelog.js";

const version = process.argv[2];

try {
  const notes = extractUnreleased(readFileSync("CHANGELOG.md", "utf8"));
  if (version) console.log(`## v${version}\n`);
  console.log(notes);
} catch (error: unknown) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
