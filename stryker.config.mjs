// @ts-check

/** @type {import("@stryker-mutator/api/core").PartialStrykerOptions} */
const config = {
  concurrency: 2,
  coverageAnalysis: "perTest",
  mutate: [
    "src/sanitizer/policy.ts",
    "src/sanitizer/rawText.ts",
    "src/utils/htmlEntities.ts",
    "src/utils/securityUtils.ts",
  ],
  reporters: ["clear-text", "progress"],
  testRunner: "vitest",
  thresholds: {
    high: 95,
    low: 90,
    break: 90,
  },
  timeoutMS: 10_000,
};

export default config;
