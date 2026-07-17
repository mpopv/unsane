# Contributing to Unsane

Thank you for your interest in contributing!

## Setup

1. Install dependencies without running build scripts:
   ```bash
   npm install --ignore-scripts
   ```
2. Run the linter and tests:
   ```bash
   npm run lint
   npm test
   ```
3. Build the project when needed:
   ```bash
   npm run build
   ```
4. Run the package smoke test before release-facing changes:
   ```bash
   npm run smoke:package
   ```

The build output is created in the `dist` directory. This folder is generated and
should **not** be committed. If you accidentally create it, run `npm run clean`
or simply delete the directory before committing your changes.

## Release

Releases are started locally but published from GitHub Actions:

```bash
bin/release.sh 0.0.20
```

The script requires a clean `main` branch that matches `origin/main`, runs the
full verification gate, creates the version commit and tag, pushes them, and
creates a GitHub release. The `Publish Package` workflow then publishes to npm
using trusted publishing / OIDC. Release notes are generated from the
`Unreleased` section of `CHANGELOG.md`.

Configure the npm package's trusted publisher to point at
`.github/workflows/publish.yml` before relying on this path.

After GitHub Actions publishes the package, verify the released artifact from
the public npm registry:

```bash
npm run verify:release -- 0.0.20
```

This checks npm metadata, installs `unsane@<version>` into a temporary consumer,
and verifies ESM, CLI, and TypeScript consumption.
