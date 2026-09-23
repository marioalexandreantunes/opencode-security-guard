// Empty-LOG_FILE guard coverage (strengthen-paths-mutation-tests).
// With `SECURITY_GUARD_LOG=""` before import, `if (!log)` must keep every
// ordinary path non-sensitive. Its own process; extras unset.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/paths-log-empty.test.mts

import assert from "node:assert/strict"
import { test } from "node:test"

delete process.env.SECURITY_GUARD_EXTRA_PATHS
process.env.SECURITY_GUARD_LOG = ""

const { isSensitivePath } = await import("../../src/paths.ts")

test("empty log: an ordinary path is not sensitive", () => {
    assert.equal(isSensitivePath("src/main.ts"), false)
    assert.equal(isSensitivePath("notes.txt"), false)
})
