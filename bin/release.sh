#!/usr/bin/env bash
set -euo pipefail

# Usage: ./release.sh 0.0.2

VERSION=${1:-}

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.0.2"
  exit 1
fi

# Optional sanity checks:
# 1) Make sure you’re npm-logged in
npm whoami >/dev/null 2>&1 || {
  echo "Not logged into npm. Run 'npm login' first."
  exit 1
}

# 2) Run tests
npm run test

# Bump version, commit & tag: includes "chore: release v0.0.2"
npm version "$VERSION" -m "chore: release v%s"

# Push commits and tag
git push origin main --follow-tags

# Create GitHub release (requires GitHub CLI, 'gh')
if command -v gh &> /dev/null; then
  gh release create "v$VERSION" \
    --title "v$VERSION" \
    --notes "Release $VERSION"
else
  echo "GitHub CLI not found. Skipping GitHub release creation."
  echo "Consider installing GitHub CLI and creating release manually."
fi

# Publish to npm
npm publish --access public
