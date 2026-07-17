import { performance } from "node:perf_hooks";
import { sanitize } from "../dist/index.js";

const workloads = [
  {
    name: "plain text",
    input: "A short message with ordinary punctuation. ".repeat(3),
    iterations: 30_000,
    minimumOpsPerSecond: 40_000,
  },
  {
    name: "safe fragment",
    input:
      '<div class="card"><h2>Title</h2><p>Hello <strong>world</strong>.</p><a href="/docs">Docs</a></div>',
    iterations: 10_000,
    minimumOpsPerSecond: 25_000,
  },
  {
    name: "attribute heavy",
    input: `<a ${Array.from(
      { length: 40 },
      (_, index) => `data-${index}="value-${index}"`,
    ).join(" ")} href="https://example.com" target="_blank">link</a>`,
    iterations: 5_000,
    minimumOpsPerSecond: 10_000,
  },
  {
    name: "raw content rejection",
    input: '<script type="text/javascript">alert(1)</script>'.repeat(100),
    iterations: 1_000,
    minimumOpsPerSecond: 8_000,
  },
  {
    name: "hostile nesting",
    input: `${"<div>".repeat(1_000)}${"</span>".repeat(1_000)}`,
    iterations: 300,
    minimumOpsPerSecond: 250,
  },
];

function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

function benchmark(workload) {
  let checksum = 0;
  const warmupIterations = Math.min(workload.iterations, 500);

  for (let index = 0; index < warmupIterations; index++) {
    checksum += sanitize(workload.input, { maxInputLength: Infinity }).length;
  }

  const samples = Array.from({ length: 3 }, () => {
    const start = performance.now();
    for (let index = 0; index < workload.iterations; index++) {
      checksum += sanitize(workload.input, { maxInputLength: Infinity }).length;
    }
    return performance.now() - start;
  });
  const durationMs = median(samples);

  return {
    name: workload.name,
    iterations: workload.iterations,
    durationMs,
    opsPerSecond: (workload.iterations / durationMs) * 1_000,
    minimumOpsPerSecond: workload.minimumOpsPerSecond,
    checksum,
  };
}

const results = workloads.map(benchmark);

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(results, null, 2));
} else {
  console.table(
    results.map(({ name, durationMs, opsPerSecond, minimumOpsPerSecond }) => ({
      workload: name,
      "median ms": durationMs.toFixed(2),
      "ops/sec": Math.round(opsPerSecond),
      minimum: minimumOpsPerSecond,
    })),
  );
}

if (process.argv.includes("--check")) {
  const failures = results.filter(
    ({ opsPerSecond, minimumOpsPerSecond }) =>
      opsPerSecond < minimumOpsPerSecond,
  );

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(
        `${failure.name}: ${Math.round(failure.opsPerSecond)} ops/sec < ${failure.minimumOpsPerSecond} ops/sec`,
      );
    }
    process.exitCode = 1;
  } else {
    console.log("Performance floors: passed");
  }
}
