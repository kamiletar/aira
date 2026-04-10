#!/usr/bin/env bash
set -euo pipefail

# Release script for Aira
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 0.3.4

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.3.4"
  exit 1
fi

# Validate semver format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "Error: version must be semver (e.g., 0.3.4 or 0.4.0-rc.1)"
  exit 1
fi

TAG="v${VERSION}"

# Check tag doesn't already exist
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Error: tag $TAG already exists"
  exit 1
fi

# Check working tree is clean
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Error: working tree is not clean. Commit or stash changes first."
  exit 1
fi

echo "Releasing Aira $TAG..."

# 1. Update workspace version
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

# 2. Update Android version
IFS='.' read -r MAJOR MINOR PATCH <<< "${VERSION%%-*}"
VERSION_CODE=$((MAJOR * 10000 + MINOR * 100 + PATCH))
sed -i "s/versionCode = .*/versionCode = ${VERSION_CODE}/" mobile/android/app/build.gradle.kts
sed -i "s/versionName = \".*\"/versionName = \"${VERSION}\"/" mobile/android/app/build.gradle.kts

# 3. Refresh Cargo.lock
cargo check --workspace 2>/dev/null

# 4. Commit
git add Cargo.toml Cargo.lock mobile/android/app/build.gradle.kts
git commit -m "chore: release ${TAG}"

# 5. Tag
git tag -a "$TAG" -m "Release ${TAG}"

# 6. Push
echo "Pushing to origin..."
git push origin HEAD
git push origin "$TAG"

echo ""
echo "Done! Release ${TAG} pushed."
echo "GitHub Actions will build and publish the release."
echo "Track progress: https://github.com/kamiletar/aira/actions"
