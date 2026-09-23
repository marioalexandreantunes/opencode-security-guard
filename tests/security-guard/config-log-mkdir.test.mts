// security-guard config recursive log-directory creation
// (strengthen-config-mutation-tests). Env is set before import; this file runs
// in its own process.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/config-log-mkdir.test.mts

import assert from "node:assert/strict"
import { existsSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { test } from "node:test"

const base = mkdtempSync(join(tmpdir(), "sg-mkdir-"))
const LOG = join(base, "missing", "nested", "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const cfg = await import("../../src/config.ts")

test("import: a missing parent directory is created recursively", () => {
    assert.equal(cfg.LOG_FILE, LOG, "the configured path is kept when it can be created")
    assert.ok(existsSync(dirname(LOG)), "the nested directory must be created")
})
