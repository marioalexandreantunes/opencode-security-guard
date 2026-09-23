// security-guard logPath policy suite (log-schema hygiene): paths under the
// project root are relativized, the root itself is ".", outside paths stay
// absolute and normalized, an unset base degrades to the absolute, and the
// policy is purely lexical (no filesystem access).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/log-path.test.mts

import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-log-path-")), "guard.log")

const cfg = await import("../../src/config.ts")
const base = mkdtempSync(join(tmpdir(), "sg-log-base-"))

test("logPath: an unset base degrades to the normalized absolute", () => {
    const target = join(base, "note.env")
    assert.equal(cfg.logPath(target), cfg.norm(target), "no base set yet: the path passes through normalized")
})

test("logPath: a path under the base is relativized with / separators", () => {
    cfg.setLogBase(base)
    assert.equal(cfg.logPath(join(base, "a", "b.txt")), "a/b.txt")
    assert.equal(cfg.logPath(join(base, ".security-guard", "guard.log")), ".security-guard/guard.log")
})

test("logPath: the base itself is logged as a dot", () => {
    assert.equal(cfg.logPath(base), ".")
})

test("logPath: a path outside the base stays absolute and normalized", () => {
    const outside = join(mkdtempSync(join(tmpdir(), "sg-log-out-")), "secret.txt")
    assert.equal(cfg.logPath(outside), cfg.norm(outside))
    // A path with an interior `..` resolves outside the base: kept as provided
    // (separator-normalized), never rewritten to a `..`-relative form.
    const external = join(base, "..", "elsewhere.txt")
    assert.equal(cfg.logPath(external), cfg.norm(external))
})

test("logPath: an already-relative input passes through untouched", () => {
    assert.equal(cfg.logPath(".env"), ".env")
    assert.equal(cfg.logPath("sub/dir/file.txt"), "sub/dir/file.txt")
})

test("logPath: purely lexical — a nonexistent path is sanitized without fs access", () => {
    const missing = join(base, "no", "such", "file.env")
    assert.equal(cfg.logPath(missing), "no/such/file.env", "relative below the base without touching the disk")
    assert.equal(cfg.logPath(missing), "no/such/file.env", "deterministic: same input, same output")
})
