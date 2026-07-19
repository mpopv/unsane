#!/usr/bin/env tsx
import fs from "node:fs";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { build } from "esbuild";

const gzip = promisify(zlib.gzip);
const brotliCompress = promisify(zlib.brotliCompress);

const budgets = {
  bundle: {
    minified: 10 * 1024,
    gzip: 4 * 1024,
    brotli: 3.5 * 1024,
  },
  package: {
    packed: 20 * 1024,
    unpacked: 100 * 1024,
    files: 32,
  },
};

interface PackageStats {
  size: number;
  unpackedSize: number;
  entryCount: number;
}

interface BundleStats {
  minified: number;
  gzip: number;
  brotli: number;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(2)} KB`;
}

function ensureBuild(): void {
  if (fs.existsSync("dist/index.js")) return;

  console.log("Build artifacts missing. Running npm run build first.\n");
  execFileSync("npm", ["run", "build"], { stdio: "inherit" });
}

async function measureConsumerBundle(): Promise<BundleStats> {
  const result = await build({
    entryPoints: ["dist/index.js"],
    bundle: true,
    format: "esm",
    legalComments: "none",
    logLevel: "silent",
    minify: true,
    platform: "neutral",
    target: "es2022",
    treeShaking: true,
    write: false,
  });
  const contents = result.outputFiles[0].contents;

  return {
    minified: contents.byteLength,
    gzip: (await gzip(contents)).byteLength,
    brotli: (await brotliCompress(contents)).byteLength,
  };
}

function measurePackage(): PackageStats {
  const output = execFileSync(
    "npm",
    ["pack", "--dry-run", "--json", "--ignore-scripts"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  const [stats] = JSON.parse(output) as PackageStats[];

  if (!stats) throw new Error("npm pack did not return package statistics");
  return stats;
}

function enforceBudget(
  failures: string[],
  label: string,
  actual: number,
  budget: number,
  format: (value: number) => string = formatBytes,
): void {
  if (actual > budget) {
    failures.push(`${label}: ${format(actual)} > ${format(budget)}`);
  }
}

async function main(): Promise<void> {
  ensureBuild();

  const bundle = await measureConsumerBundle();
  const packageStats = measurePackage();

  console.log("Consumer ESM bundle:");
  console.log(`  Minified: ${formatBytes(bundle.minified)}`);
  console.log(`  Minified + gzip: ${formatBytes(bundle.gzip)}`);
  console.log(`  Minified + Brotli: ${formatBytes(bundle.brotli)}\n`);

  console.log("Published package dry run:");
  console.log(`  Tarball: ${formatBytes(packageStats.size)}`);
  console.log(`  Unpacked: ${formatBytes(packageStats.unpackedSize)}`);
  console.log(`  Files: ${packageStats.entryCount}\n`);

  const failures: string[] = [];
  enforceBudget(
    failures,
    "bundle minified",
    bundle.minified,
    budgets.bundle.minified,
  );
  enforceBudget(failures, "bundle gzip", bundle.gzip, budgets.bundle.gzip);
  enforceBudget(
    failures,
    "bundle Brotli",
    bundle.brotli,
    budgets.bundle.brotli,
  );
  enforceBudget(
    failures,
    "package tarball",
    packageStats.size,
    budgets.package.packed,
  );
  enforceBudget(
    failures,
    "package unpacked",
    packageStats.unpackedSize,
    budgets.package.unpacked,
  );
  enforceBudget(
    failures,
    "package files",
    packageStats.entryCount,
    budgets.package.files,
    String,
  );

  if (failures.length > 0) {
    for (const failure of failures)
      console.error(`Size budget exceeded: ${failure}`);
    process.exitCode = 1;
    return;
  }

  console.log("Real bundle and package size budgets: passed");
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
