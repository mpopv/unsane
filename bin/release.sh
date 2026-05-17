#!/usr/bin/env bash
set -euo pipefail

# Usage: bin/release.sh 0.0.20

VERSION=${1:-}
MAIN_BRANCH=${MAIN_BRANCH:-main}
REMOTE=${REMOTE:-origin}
NOTES_FILE=$(mktemp)

cleanup() {
  rm -f "$NOTES_FILE"
}
trap cleanup EXIT

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.0.20"
  exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Version must be a semver string like 0.0.20 or 0.0.20-beta.1."
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI is required because publishing is triggered by a GitHub release."
  exit 1
fi

current_branch=$(git rev-parse --abbrev-ref HEAD)
if [[ "$current_branch" != "$MAIN_BRANCH" ]]; then
  echo "Release must run from $MAIN_BRANCH; current branch is $current_branch."
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Working tree must be clean before release."
  exit 1
fi

git fetch "$REMOTE" "$MAIN_BRANCH" --tags

local_head=$(git rev-parse HEAD)
remote_head=$(git rev-parse "$REMOTE/$MAIN_BRANCH")
if [[ "$local_head" != "$remote_head" ]]; then
  echo "Local $MAIN_BRANCH must match $REMOTE/$MAIN_BRANCH before release."
  exit 1
fi

if git rev-parse "v$VERSION" >/dev/null 2>&1; then
  echo "Tag v$VERSION already exists."
  exit 1
fi

gh auth status >/dev/null

npm ci
npm audit
npm run lint
npm test
npm run build
npm run analyze-size
npm pack --dry-run
npm run smoke:package
node scripts/release-notes.mjs "$VERSION" > "$NOTES_FILE"

npm version "$VERSION" -m "chore: release v%s"
npm publish --dry-run
git push "$REMOTE" "$MAIN_BRANCH" --follow-tags

gh release create "v$VERSION" \
  --target "$MAIN_BRANCH" \
  --title "v$VERSION" \
  --notes-file "$NOTES_FILE"

echo "Created GitHub release v$VERSION."
echo "npm publishing is handled by .github/workflows/publish.yml via trusted publishing."
