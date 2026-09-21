#!/usr/bin/env bash
# Runs the fast quality gates in order and fails on the first failure.
# Mutation testing is intentionally excluded (it runs as the nightly job).
set -euo pipefail

gates=(
    "typecheck|npm run typecheck"
    "lint|npm run lint"
    "format:check|npm run format:check"
    "audit|npm audit --audit-level=high"
    "test|npm test"
    "test:property|npm run test:property"
    "coverage|npm run coverage"
    "build|npm run build"
    "integration:dist|npm run integration:dist"
    "smoke:dist|npm run smoke:dist"
)

for entry in "${gates[@]}"; do
    name="${entry%%|*}"
    command="${entry#*|}"
    echo "==> ${name}: ${command}"
    if ! eval "${command}"; then
        echo "FAILED: ${name}" >&2
        exit 1
    fi
done

echo "All fast gates passed."
