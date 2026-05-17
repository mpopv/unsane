#!/usr/bin/env tsx
import fs from "fs";
import zlib from "zlib";
import { promisify } from "util";
import { execFileSync } from "child_process";

const readFile = promisify(fs.readFile);
const gzip = promisify(zlib.gzip);

// ESM files loaded by the public package entry point.
const runtimeImportPaths = [
  "dist/index.js",
  "dist/sanitizer/htmlSanitizer.js",
  "dist/sanitizer/config.js",
  "dist/utils/htmlEntities.js",
  "dist/utils/securityUtils.js",
];

interface FileDetail {
  file: string;
  sourceSize: number;
  sourceGzipSize: number;
  minifiedSize: number;
  minifiedGzipSize: number;
}

function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function ensureBuildArtifacts(paths: string[]): void {
  const missingFiles = paths.filter((file) => !fs.existsSync(file));

  if (missingFiles.length === 0) return;

  console.log("Build artifacts missing. Running npm run build first.\n");
  execFileSync("npm", ["run", "build"], { stdio: "inherit" });
}

async function minifyCode(
  filePath: string
): Promise<{ minified: string; size: number; gzipSize: number }> {
  const tempOutputPath = `${filePath}.min.js`;

  try {
    execFileSync(
      "npx",
      ["terser", filePath, "--compress", "--mangle", "--output", tempOutputPath],
      { stdio: "pipe" }
    );

    const minified = await readFile(tempOutputPath, "utf8");
    const size = Buffer.byteLength(minified);
    const gzipContent = await gzip(Buffer.from(minified));

    return { minified, size, gzipSize: gzipContent.length };
  } finally {
    if (fs.existsSync(tempOutputPath)) {
      fs.unlinkSync(tempOutputPath);
    }
  }
}

async function analyzeRuntimeImports(): Promise<void> {
  try {
    ensureBuildArtifacts(runtimeImportPaths);

    const packageJsonContent = await readFile("package.json", "utf8");
    const packageJson = JSON.parse(packageJsonContent);

    console.log(
      `\nAnalyzing runtime import sizes for: ${
        packageJson.name || "unsane"
      } v${packageJson.version || "development"}\n`
    );

    const fileDetails: FileDetail[] = [];
    const sourceParts: string[] = [];
    const minifiedParts: string[] = [];

    for (const file of runtimeImportPaths) {
      const source = await readFile(file, "utf8");
      const sourceSize = Buffer.byteLength(source);
      const sourceGzipSize = (await gzip(Buffer.from(source))).length;
      const { minified, size: minifiedSize, gzipSize: minifiedGzipSize } =
        await minifyCode(file);

      sourceParts.push(source);
      minifiedParts.push(minified);
      fileDetails.push({
        file,
        sourceSize,
        sourceGzipSize,
        minifiedSize,
        minifiedGzipSize,
      });
    }

    fileDetails.sort((a, b) => b.sourceSize - a.sourceSize);

    console.log("Runtime Import Files:");
    console.log(
      "-------------------------------------------------------------------------------"
    );
    console.log(
      "  File                             | Source   | Gzip     | Minified | Min+Gzip"
    );
    console.log(
      "-------------------------------------------------------------------------------"
    );

    for (const detail of fileDetails) {
      console.log(
        `  ${detail.file.padEnd(32)} | ${formatBytes(detail.sourceSize).padEnd(
          8
        )} | ${formatBytes(detail.sourceGzipSize).padEnd(8)} | ${formatBytes(
          detail.minifiedSize
        ).padEnd(8)} | ${formatBytes(detail.minifiedGzipSize)}`
      );
    }

    console.log(
      "-------------------------------------------------------------------------------\n"
    );

    const combinedSource = sourceParts.join("\n");
    const combinedMinified = minifiedParts.join("\n");
    const sourceSize = Buffer.byteLength(combinedSource);
    const sourceGzipSize = (await gzip(Buffer.from(combinedSource))).length;
    const minifiedSize = Buffer.byteLength(combinedMinified);
    const minifiedGzipSize = (await gzip(Buffer.from(combinedMinified))).length;

    console.log("Size Summary:");
    console.log(`  - Runtime import closure: ${formatBytes(sourceSize)}`);
    console.log(`  - Runtime import closure gzipped: ${formatBytes(sourceGzipSize)}`);
    console.log(`  - Minified runtime closure: ${formatBytes(minifiedSize)}`);
    console.log(
      `  - Minified + gzipped runtime closure: ${formatBytes(minifiedGzipSize)}`
    );
    console.log(
      `  - Compression ratio: ${(
        100 -
        (minifiedGzipSize / sourceSize) * 100
      ).toFixed(1)}%\n`
    );
  } catch (error) {
    console.error(
      "Error analyzing runtime imports:",
      error instanceof Error ? error.message : String(error)
    );
    process.exit(1);
  }
}

analyzeRuntimeImports();
