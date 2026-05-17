#!/usr/bin/env node
import { readFileSync } from "fs";

const version = process.argv[2] || "";
const changelog = readFileSync("CHANGELOG.md", "utf8");
const match = changelog.match(/## Unreleased\s+([\s\S]*?)(?=\n## |\s*$)/);

if (!match || !match[1].trim()) {
  console.error("No Unreleased changelog notes found.");
  process.exit(1);
}

if (version) {
  console.log(`## v${version}\n`);
}

console.log(match[1].trim());
