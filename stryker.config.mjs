// @ts-check

/** @type {import("@stryker-mutator/api/core").PartialStrykerOptions} */
const config = {
  concurrency: 2,
  coverageAnalysis: "perTest",
  ignoreStatic: true,
  mutate: ["src/utils/securityUtils.ts"],
  reporters: ["clear-text", "progress"],
  testRunner: "vitest",
  thresholds: {
    high: 100,
    low: 100,
    break: 100,
  },
  timeoutMS: 10_000,
};

export default config;
