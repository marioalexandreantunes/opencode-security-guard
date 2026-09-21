// security-guard log-level env semantics (strengthen-config-mutation-tests).
// The minimum level is read once at import; this file runs in its own process.
// `warn` (rank 2) is deliberate: at rank 0 or 1 the outer
// `... ?? LEVEL_RANK.info` -> `&&` mutant is equivalent, so a higher level is
// required to distinguish it.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/config-log-level.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-level-")), "guard.log")
process.env.SECURITY_GUARD_LOG_LEVEL = "warn"
delete process.env.SECURITY_GUARD_MODE
delete process.env.SECURITY_GUARD_QUIET

const cfg = await import("../../src/config.ts")

test("log-level: SECURITY_GUARD_LOG_LEVEL=warn raises the minimum rank", () => {
    assert.equal(cfg.logAllows("debug"), false)
    assert.equal(cfg.logAllows("info"), false, "the outer rank fallback must keep the warn minimum")
    assert.equal(cfg.logAllows("warn"), true)
    assert.equal(cfg.logAllows("error"), true)
})
