#!/usr/bin/env tsx
import { readFileSync, writeFileSync } from "node:fs";
import { rollUnreleased } from "./changelog.js";

try {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8")) as {
    version?: unknown;
  };
  if (typeof packageJson.version !== "string") {
    throw new Error("package.json is missing a string version.");
  }

  const changelog = readFileSync("CHANGELOG.md", "utf8");
  const date = new Date().toISOString().slice(0, 10);
  writeFileSync(
    "CHANGELOG.md",
    rollUnreleased(changelog, packageJson.version, date),
  );
} catch (error: unknown) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
