#!/usr/bin/env bash
# Version bump — single-source-of-truth update.
#
# cyrius.cyml uses `version = "${file:VERSION}"`, so the manifest
# does not need editing. CHANGELOG / docs are manual.
#
# Usage: ./scripts/version-bump.sh 2.1.1

set -euo pipefail
[ $# -ne 1 ] && { echo "Usage: $0 <version>"; exit 1; }
NEW_VERSION="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "$NEW_VERSION" > "$REPO_ROOT/VERSION"
echo "Bumped to ${NEW_VERSION}. Tag + push when ready."
