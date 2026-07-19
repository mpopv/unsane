#!/usr/bin/env node
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";
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

function runBin(cwd, binName, args, options = {}) {
  const binPath = join(
    cwd,
    "node_modules",
    ".bin",
    process.platform === "win32" ? `${binName}.cmd` : binName,
  );
  return run(binPath, args, { cwd, ...options });
}

async function readPublishedMetadata(packageSpec) {
  let lastError;

  for (let attempt = 1; attempt <= 6; attempt++) {
    try {
      return JSON.parse(
        run("npm", ["view", packageSpec, "version", "dist", "--json"]),
      );
    } catch (error) {
      lastError = error;
      if (attempt === 6) break;

      console.log(
        `Waiting for ${packageSpec} to reach the registry (attempt ${attempt}/6)...`,
      );
      await new Promise((resolve) => setTimeout(resolve, 10_000));
    }
  }

  throw lastError;
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
    input: '<a href="javascript:alert(1)">bad</a><p>ok</p>',
    encoding: "utf8",
  });

  if (result.error) throw result.error;

  if (result.status !== 0) {
    throw new Error(
      `CLI release check failed with exit ${result.status}: ${result.stderr}`,
    );
  }

  if (result.stdout !== "<a>bad</a><p>ok</p>") {
    throw new Error(`Unexpected CLI output: ${JSON.stringify(result.stdout)}`);
  }
}

const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
const version = process.argv[2] || packageJson.version;
const packageSpec = `unsane@${version}`;
const tempRoot = mkdtempSync(join(tmpdir(), "unsane-post-release-"));

try {
  const npmView = await readPublishedMetadata(packageSpec);

  if (npmView.version !== version) {
    throw new Error(`Expected npm version ${version}, got ${npmView.version}`);
  }

  if (!npmView.dist?.integrity || !npmView.dist?.tarball) {
    throw new Error(`Registry metadata for ${packageSpec} is incomplete.`);
  }

  console.log(`Verified npm metadata for ${packageSpec}`);
  console.log(`Tarball: ${npmView.dist.tarball}`);

  const consumerDir = join(tempRoot, "consumer");
  mkdirSync(consumerDir);
  writeFileSync(join(consumerDir, "package.json"), '{"type":"module"}\n');

  run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--prefer-online",
      packageSpec,
      "typescript@^5.9.3",
    ],
    { cwd: consumerDir, stdio: "inherit" },
  );

  const installedPackage = JSON.parse(
    readFileSync(join(consumerDir, "node_modules", "unsane", "package.json")),
  );
  if (installedPackage.version !== version) {
    throw new Error(
      `Installed unsane ${installedPackage.version}, expected ${version}.`,
    );
  }

  writeFileSync(
    join(consumerDir, "esm-check.mjs"),
    `import { sanitize, escape, encode, decode } from "unsane";

if (sanitize('<a href="javascript:alert(1)">bad</a><p>ok</p>') !== "<a>bad</a><p>ok</p>") {
  throw new Error("ESM sanitize failed");
}
if (decode(encode(escape("<x>"))) !== "&lt;x&gt;") {
  throw new Error("ESM entity helpers failed");
}
`,
  );
  runNode(join(consumerDir, "esm-check.mjs"), consumerDir);

  writeFileSync(
    join(consumerDir, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          module: "NodeNext",
          moduleResolution: "NodeNext",
          noEmit: true,
          strict: true,
          target: "ES2020",
        },
        include: ["types-check.ts"],
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(consumerDir, "types-check.ts"),
    `import { sanitize, type SanitizerOptions } from "unsane";

const options: SanitizerOptions = { allowedTags: ["a"] };
const output: string = sanitize("<a>ok</a>", options);
void output;
`,
  );
  runBin(consumerDir, "tsc", ["--project", "tsconfig.json"], {
    stdio: "inherit",
  });
  assertCli(consumerDir);

  console.log(`Post-release verification passed for ${packageSpec}.`);
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
