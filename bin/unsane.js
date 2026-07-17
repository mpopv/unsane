#!/usr/bin/env node
import { sanitize } from "../dist/index.js";
import { DEFAULT_MAX_INPUT_LENGTH } from "../dist/sanitizer/config.js";

let data = "";
let inputTooLong = false;
process.stdin.setEncoding("utf8");

if (process.stdin.isTTY) {
  console.error('Usage: echo "<html>" | unsane');
  process.exit(1);
}

process.stdin.on("data", (chunk) => {
  if (inputTooLong) return;

  if (data.length + chunk.length > DEFAULT_MAX_INPUT_LENGTH) {
    inputTooLong = true;
    data = "";
    console.error(`Input exceeds maxInputLength ${DEFAULT_MAX_INPUT_LENGTH}.`);
    process.exitCode = 1;
    process.stdin.destroy();
    return;
  }

  data += chunk;
});

process.stdin.on("end", () => {
  if (inputTooLong) return;

  try {
    const clean = sanitize(data);
    process.stdout.write(clean);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }
});
