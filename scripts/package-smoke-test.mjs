#!/usr/bin/env node
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { execFileSync, spawnSync } from "child_process";

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: options.stdio ?? "pipe",
    ...options,
  });
}

function runNode(scriptPath, cwd) {
  run(process.execPath, [scriptPath], { cwd, stdio: "inherit" });
}

function assertCli(cwd) {
  const binPath = join(
    cwd,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "unsane.cmd" : "unsane"
  );
  const result = spawnSync(binPath, [], {
    cwd,
    input: '<div onclick="alert(1)">ok</div>',
    encoding: "utf8",
  });

  if (result.error) throw result.error;

  if (result.status !== 0) {
    throw new Error(
      `CLI smoke test failed with exit ${result.status}: ${result.stderr}`
    );
  }

  if (result.stdout !== "<div>ok</div>") {
    throw new Error(`Unexpected CLI output: ${JSON.stringify(result.stdout)}`);
  }
}

const tempRoot = mkdtempSync(join(tmpdir(), "unsane-package-smoke-"));

try {
  const packDir = join(tempRoot, "pack");
  const consumerDir = join(tempRoot, "consumer");

  mkdirSync(packDir);
  mkdirSync(consumerDir);

  const packOutput = run("npm", [
    "pack",
    "--json",
    "--pack-destination",
    packDir,
  ]);
  const packResult = JSON.parse(packOutput)[0];
  const tarballPath = resolve(packDir, packResult.filename);

  writeFileSync(join(consumerDir, "package.json"), '{"type":"module"}\n');
  run(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarballPath],
    {
      cwd: consumerDir,
      stdio: "inherit",
    }
  );

  const esmScript = join(consumerDir, "esm-smoke.mjs");
  writeFileSync(
    esmScript,
    `import { sanitize, escape, encode, decode } from "unsane";

if (sanitize('<div onclick="alert(1)">ok</div>') !== "<div>ok</div>") {
  throw new Error("ESM sanitize failed");
}
if (escape('<x>') !== "&lt;x&gt;") {
  throw new Error("ESM escape failed");
}
if (decode(encode("<x>")) !== "<x>") {
  throw new Error("ESM encode/decode failed");
}
`
  );
  runNode(esmScript, consumerDir);

  const cjsScript = join(consumerDir, "cjs-smoke.cjs");
  writeFileSync(
    cjsScript,
    `const { sanitize } = require("unsane");

if (sanitize('<img src="javascript:alert(1)"><span>ok</span>') !== "<img /><span>ok</span>") {
  throw new Error("CJS sanitize failed");
}
`
  );
  runNode(cjsScript, consumerDir);
  assertCli(consumerDir);

  console.log("Package smoke test passed.");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
