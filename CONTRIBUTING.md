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

The build output is created in the `dist` directory. This folder is generated and
should **not** be committed. If you accidentally create it, run `npm run clean`
or simply delete the directory before committing your changes.

