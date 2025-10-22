# Repository Guidelines

## Project Structure & Module Organization
Source resides in `src/`: `src/index.ts` exposes the public API, `src/sanitizer/` houses the sanitization pipeline, and `src/utils/` contains encoding helpers. Unit tests sit alongside code as `*.test.ts` (for example `src/exports.test.ts`). CLI tooling lives in `bin/unsane`. Build outputs flow to `dist/`; regenerate instead of editing. Coverage reports land in `coverage/`, and bundle-size checks use `measure-size.ts`.

## Build, Test, and Development Commands
- `npm install` — bootstrap dependencies.
- `npm run build` — compile ESM and CJS bundles into `dist/`.
- `npm run test` — execute Vitest with V8 coverage and strict thresholds.
- `npm run lint` — run ESLint with Prettier integration across TypeScript and scripts.
- `npm run analyze-size` — execute `measure-size.ts` to watch publishing footprint.
- `npm run clean` — remove `dist/` for a clean rebuild.
- `npm run release` — maintainer script that runs build/test and stages publish artifacts.

## Coding Style & Naming Conventions
TypeScript plus modern ESM is the standard. Prettier (2-space indent, double quotes, trailing semicolons) and ESLint must pass before committing. Use camelCase for variables and functions, PascalCase for types and classes, and kebab-case filenames (`measure-size.ts`). Tests should mirror their subject file name with a `.test.ts` suffix and live next to the module.

## Testing Guidelines
Vitest is configured in `vite.config.ts` for the Node runtime with 100% thresholds for lines, branches, functions, and statements. Update or add `*.test.ts` files whenever behavior changes and rerun `npm run test` to refresh reports in `coverage/`. Prefer descriptive `describe`/`it` names that encode the expected API contract, and pair sanitization changes with examples covering both allowed and rejected markup.

## Commit & Pull Request Guidelines
Commits use conventional prefixes (`feat`, `fix`, `chore`, optional scope) in imperative mood (e.g., `fix: normalize entity escaping`) and should stay focused. Run `npm run lint` and `npm run test` before pushing. Pull requests must outline intent, link issues, and summarize verification steps (tests, size analysis, screenshots for CLI output when helpful). Flag breaking changes or new configuration, and include before/after snippets when sanitization behavior shifts.
