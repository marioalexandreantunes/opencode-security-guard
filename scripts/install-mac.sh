#!/usr/bin/env bash
# Build the plugin and copy the bundle into the global opencode plugins directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${HOME}/.config/opencode/plugins"
DEST="${DEST_DIR}/security-guard.js"

cd "$REPO_ROOT"
npm run build

mkdir -p "$DEST_DIR"
cp "dist/security-guard.js" "$DEST"

echo "Installed: $DEST"
echo "Restart opencode to load the new bundle."
