#!/usr/bin/env bash
set -euo pipefail

# Usage: bin/release.sh 0.1.0

VERSION=${1:-}
MAIN_BRANCH=${MAIN_BRANCH:-main}
REMOTE=${REMOTE:-origin}
RELEASE_BRANCH="release/v$VERSION"
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

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "Working tree must be clean before release."
  exit 1
fi

git fetch "$REMOTE" "$MAIN_BRANCH" --tags

local_head=$(git rev-parse HEAD)
remote_head=$(git rev-parse "$REMOTE/$MAIN_BRANCH")
if [[ "$local_head" != "$remote_head" ]]; then
  echo "Release must start from $REMOTE/$MAIN_BRANCH."
  exit 1
fi

if git rev-parse "v$VERSION" >/dev/null 2>&1; then
  echo "Tag v$VERSION already exists."
  exit 1
fi

if git ls-remote --exit-code --heads "$REMOTE" "$RELEASE_BRANCH" >/dev/null 2>&1; then
  echo "Release branch $RELEASE_BRANCH already exists on $REMOTE."
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

git switch -c "$RELEASE_BRANCH"
npm version "$VERSION" --no-git-tag-version
git add package.json package-lock.json CHANGELOG.md
git commit -m "chore: release v$VERSION"
npm publish --dry-run --ignore-scripts
git push -u "$REMOTE" "$RELEASE_BRANCH"

PR_URL=$(gh pr create \
  --base "$MAIN_BRANCH" \
  --head "$RELEASE_BRANCH" \
  --title "chore: release v$VERSION" \
  --body "Prepare v$VERSION and roll the Unreleased changelog into a dated release section.")

check_count=0
for _ in {1..30}; do
  check_count=$(gh pr view "$PR_URL" --json statusCheckRollup --jq '.statusCheckRollup | length')
  if (( check_count > 0 )); then
    break
  fi
  sleep 2
done

if (( check_count == 0 )); then
  echo "No checks appeared for $PR_URL."
  exit 1
fi

gh pr checks "$PR_URL" --watch --interval 10
gh pr merge "$PR_URL" --merge

git fetch "$REMOTE" "$MAIN_BRANCH"
release_commit=$(git rev-parse "$REMOTE/$MAIN_BRANCH")
if ! git merge-base --is-ancestor HEAD "$release_commit"; then
  echo "$REMOTE/$MAIN_BRANCH does not contain the release commit."
  exit 1
fi

git tag -a "v$VERSION" "$release_commit" -m "v$VERSION"
git push "$REMOTE" "v$VERSION"

gh release create "v$VERSION" \
  --title "v$VERSION" \
  --notes-file "$NOTES_FILE"

echo "Created GitHub release v$VERSION."
echo "npm publishing is handled by .github/workflows/publish.yml via trusted publishing."
