#!/usr/bin/env tsx
import fs from "fs";
import zlib from "zlib";
import { promisify } from "util";
import { execSync } from "child_process";

// Promisify necessary functions
const readFile = promisify(fs.readFile);
const gzip = promisify(zlib.gzip);

// Only analyze files that a client would import
const clientImportPaths = [
  "dist/src/index.js",
  "dist/src/unsane.js"
];

interface FileDetail {
  file: string;
  size: number;
  gzipSize: number;
  sizeFormatted: string;
  gzipSizeFormatted: string;
  isMinified: boolean;
}

/**
 * Format bytes to a human-readable format
 */
function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

/**
 * Minify JavaScript using Terser
 */
async function minifyCode(
  filePath: string
): Promise<{ minified: string; size: number; gzipSize: number }> {
  try {
    const tempOutputPath = `${filePath}.min.js`;

    // Run terser with subprocess to avoid memory issues
    execSync(
      `npx terser ${filePath} --compress --mangle --output ${tempOutputPath}`
    );

    // Read the minified file
    const minified = await readFile(tempOutputPath, "utf8");
    const size = Buffer.byteLength(minified);

    // Calculate gzip size
    const gzipContent = await gzip(Buffer.from(minified));
    const gzipSize = gzipContent.length;

    // Clean up temp file
    fs.unlinkSync(tempOutputPath);

    return { minified, size, gzipSize };
  } catch (error) {
    console.error(`Error minifying ${filePath}:`, error);
    return { minified: "", size: 0, gzipSize: 0 };
  }
}

/**
 * Calculate the size of client imports
 */
async function analyzeClientImports(): Promise<void> {
  try {
    // Get package info
    const packageJsonContent = await readFile("package.json", "utf8");
    const packageJson = JSON.parse(packageJsonContent);

    console.log(
      `\n📦 Analyzing client import sizes for: ${
        packageJson.name || "unsane"
      } v${packageJson.version || "development"}\n`
    );

    // Calculate size and gzipped size for each client import
    let standardSize = 0;
    let standardMinSize = 0;
    let standardMinGzipSize = 0;
    const fileDetails: FileDetail[] = [];

    for (const file of clientImportPaths) {
      try {
        if (!fs.existsSync(file)) {
          console.log(`Skipping non-existent file: ${file}`);
          continue;
        }

        const content = await readFile(file);
        const size = content.length;
        const gzipContent = await gzip(content);
        const gzipSize = gzipContent.length;
        const isMinified = file.includes(".min.js");

        if (file.includes("unsane.js")) {
          standardSize = size;

          // Minify the standard version
          const { size: minSize, gzipSize: minGzipSize } = await minifyCode(
            file
          );
          standardMinSize = minSize;
          standardMinGzipSize = minGzipSize;

          // Add this as a virtual file entry
          fileDetails.push({
            file: `${file} (minified)`,
            size: minSize,
            gzipSize: minGzipSize,
            sizeFormatted: formatBytes(minSize),
            gzipSizeFormatted: formatBytes(minGzipSize),
            isMinified: true,
          });
        }

        fileDetails.push({
          file,
          size,
          gzipSize,
          sizeFormatted: formatBytes(size),
          gzipSizeFormatted: formatBytes(gzipSize),
          isMinified,
        });
      } catch (e) {
        const error = e as Error;
        console.error(`Error processing file ${file}:`, error.message);
      }
    }

    // Sort by size (descending)
    fileDetails.sort((a, b) => b.size - a.size);

    // Display results
    console.log("📄 Client Import Sizes:");
    console.log(
      "-------------------------------------------------------------"
    );
    console.log("  File                        | Size        | Gzipped Size");
    console.log(
      "-------------------------------------------------------------"
    );
    for (const detail of fileDetails) {
      const fileName = detail.file.padEnd(30);
      const size = detail.sizeFormatted.padEnd(12);
      console.log(`  ${fileName} | ${size} | ${detail.gzipSizeFormatted}`);
    }
    console.log(
      "-------------------------------------------------------------\n"
    );

    // Summary
    console.log("📊 Size Summary:");
    console.log(`  • Unpacked: ${formatBytes(standardSize)}`);
    console.log(`  • Minified: ${formatBytes(standardMinSize)}`);
    console.log(`  • Gzipped (minified): ${formatBytes(standardMinGzipSize)}`);
    console.log(`  • Compression ratio: ${(100 - (standardMinGzipSize / standardSize) * 100).toFixed(1)}%\n`);

  } catch (error) {
    console.error(
      "Error analyzing client imports:",
      error instanceof Error ? error.message : String(error)
    );
  }
}

// Run the analysis
analyzeClientImports();