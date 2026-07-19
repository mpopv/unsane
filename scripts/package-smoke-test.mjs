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
    process.platform === "win32" ? "unsane.cmd" : "unsane",
  );
  const result = spawnSync(binPath, [], {
    cwd,
    input: '<div onclick="alert(1)">ok</div>',
    encoding: "utf8",
  });

  if (result.error) throw result.error;

  if (result.status !== 0) {
    throw new Error(
      `CLI smoke test failed with exit ${result.status}: ${result.stderr}`,
    );
  }

  if (result.stdout !== "<div>ok</div>") {
    throw new Error(`Unexpected CLI output: ${JSON.stringify(result.stdout)}`);
  }

  const oversizedResult = spawnSync(binPath, [], {
    cwd,
    input: "x".repeat(1_000_001),
    encoding: "utf8",
  });

  if (oversizedResult.status === 0) {
    throw new Error("CLI accepted input above maxInputLength.");
  }

  if (!oversizedResult.stderr.includes("Input exceeds maxInputLength")) {
    throw new Error(
      `Unexpected oversized-input error: ${JSON.stringify(oversizedResult.stderr)}`,
    );
  }
}

function runBin(cwd, binName, args) {
  const binPath = join(
    cwd,
    "node_modules",
    ".bin",
    process.platform === "win32" ? `${binName}.cmd` : binName,
  );
  run(binPath, args, { cwd, stdio: "inherit" });
}

function assertTypes(cwd) {
  writeFileSync(
    join(cwd, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          module: "NodeNext",
          moduleResolution: "NodeNext",
          noEmit: true,
          strict: true,
          target: "ES2020",
        },
        include: ["types-smoke.ts"],
      },
      null,
      2,
    ),
  );

  writeFileSync(
    join(cwd, "types-smoke.ts"),
    `import { sanitize, escape, encode, decode, type Sanitizer, type SanitizerOptions } from "unsane";

const options: SanitizerOptions = {
  allowedTags: ["a"],
  allowedAttributes: {
    a: ["href"],
    "*": ["class"],
  },
  maxInputLength: 1024,
};

const sanitized: string = sanitize('<a href="/docs" class="link">Docs</a>', options);
const escaped: string = escape(sanitized);
const encoded: string = encode(escaped);
const decoded: string = decode(encoded);
const sanitizer: Sanitizer = { sanitize };

sanitizer.sanitize(decoded, options);
`,
  );

  runBin(cwd, "tsc", ["--project", "tsconfig.json"]);
}

const EXPECTED_PACKED_FILES = [
  "LICENSE",
  "README.md",
  "bin/unsane.js",
  "dist/index.d.ts",
  "dist/index.js",
  "dist/sanitizer/config.d.ts",
  "dist/sanitizer/config.js",
  "dist/sanitizer/htmlSanitizer.d.ts",
  "dist/sanitizer/htmlSanitizer.js",
  "dist/types.d.ts",
  "dist/types.js",
  "dist/utils/htmlEntities.d.ts",
  "dist/utils/htmlEntities.js",
  "dist/utils/securityUtils.d.ts",
  "dist/utils/securityUtils.js",
  "package.json",
];

function assertPackageContents(packResult) {
  const actualFiles = packResult.files.map((file) => file.path).sort();
  const expectedFiles = [...EXPECTED_PACKED_FILES].sort();
  const actualSet = new Set(actualFiles);
  const expectedSet = new Set(expectedFiles);

  const missing = expectedFiles.filter((file) => !actualSet.has(file));
  const extra = actualFiles.filter((file) => !expectedSet.has(file));

  if (missing.length || extra.length) {
    throw new Error(
      [
        "Packed file list changed unexpectedly.",
        missing.length ? `Missing: ${missing.join(", ")}` : "",
        extra.length ? `Extra: ${extra.join(", ")}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
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
  assertPackageContents(packResult);
  const tarballPath = resolve(packDir, packResult.filename);

  writeFileSync(join(consumerDir, "package.json"), '{"type":"module"}\n');
  run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      tarballPath,
      "typescript@^5.9.3",
    ],
    {
      cwd: consumerDir,
      stdio: "inherit",
    },
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
`,
  );
  runNode(esmScript, consumerDir);

  assertCli(consumerDir);
  assertTypes(consumerDir);

  console.log("Package smoke test passed.");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
