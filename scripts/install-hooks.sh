#!/usr/bin/env bash
# Opt-in installer for the local git hooks (supplementary enforcement; the CI
# workflow is the blocking gate). Copies the committed templates from
# `scripts/hooks/` into the current repository's `.git/hooks/`.
#
# Usage: scripts/install-hooks.sh [--force]
#
# It touches nothing else: no `git config` changes, no forced installs. Hooks
# installed this way can be bypassed per-push with `git push --no-verify`.
set -euo pipefail

force=0
for arg in "$@"; do
    case "$arg" in
        --force) force=1 ;;
        -h|--help)
            echo "Usage: scripts/install-hooks.sh [--force]"
            exit 0
            ;;
        *)
            echo "install-hooks: unknown option: $arg" >&2
            echo "Usage: scripts/install-hooks.sh [--force]" >&2
            exit 2
            ;;
    esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_DIR="$(git rev-parse --git-dir)/hooks"
SRC="$REPO_ROOT/scripts/hooks/pre-push"
DEST="$HOOK_DIR/pre-push"
BACKUP="$DEST.security-guard-backup"

if [ ! -f "$SRC" ]; then
    echo "install-hooks: template not found: $SRC" >&2
    exit 1
fi
mkdir -p "$HOOK_DIR"

if [ -e "$DEST" ] && [ "$force" -eq 0 ]; then
    if [ -e "$BACKUP" ]; then
        echo "install-hooks: refusing to replace $DEST; backup already exists at $BACKUP" >&2
        echo "install-hooks: use --force to replace the existing hook explicitly" >&2
        exit 1
    fi
    cp "$DEST" "$BACKUP"
    echo "install-hooks: backed up existing pre-push hook -> $BACKUP"
fi

cp "$SRC" "$DEST"
chmod +x "$DEST"
echo "install-hooks: installed pre-push hook -> $DEST"
