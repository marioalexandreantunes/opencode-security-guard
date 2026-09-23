// security-guard config import-time fallback when the log directory cannot be
// created (strengthen-config-mutation-tests). Env is set before import; this
// file runs in its own process.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/config-log-fallback.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const blocker = join(mkdtempSync(join(tmpdir(), "sg-fallback-")), "blocker")
writeFileSync(blocker, "not a directory\n", "utf8")
process.env.SECURITY_GUARD_LOG = join(blocker, "nested", "guard.log")

const cfg = await import("../../src/config.ts")

test("import fallback: an uncreatable log directory falls back to the tmpdir log", () => {
    const expected = join(tmpdir(), "opencode-security-guard.log").replace(/\\/g, "/")
    assert.equal(cfg.LOG_FILE.replace(/\\/g, "/"), expected)
})
