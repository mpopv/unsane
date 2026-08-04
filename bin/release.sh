#!/usr/bin/env bash
set -euo pipefail

# Usage: bin/release.sh 0.1.0

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
  echo "Example: $0 0.1.0"
  exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Version must be a semver string like 0.1.0 or 0.1.0-beta.1."
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

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
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
npm run format:check
npm test
npm run build
npm run typecheck:built
npm run analyze-size:built
npm run benchmark:built
npm run test:fuzz:built
npm run smoke:package:built
npm run release:notes -- "$VERSION" > "$NOTES_FILE"

npm version "$VERSION" -m "chore: release v%s"
npm publish --dry-run --ignore-scripts
git push "$REMOTE" "$MAIN_BRANCH" --follow-tags

gh release create "v$VERSION" \
  --target "$MAIN_BRANCH" \
  --title "v$VERSION" \
  --notes-file "$NOTES_FILE"

echo "Created GitHub release v$VERSION."
echo "npm publishing is handled by .github/workflows/publish.yml via trusted publishing."
