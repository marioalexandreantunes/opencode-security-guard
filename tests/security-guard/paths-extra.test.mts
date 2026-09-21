// SECURITY_GUARD_EXTRA_PATHS build-path coverage (strengthen-paths-mutation-tests).
// The variable must be set before `paths.ts` is imported (its own process).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/paths-extra.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-extra-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
// padded valid patterns, `;` separators, empty segments, and one invalid regex.
process.env.SECURITY_GUARD_EXTRA_PATHS = "  acme-private  ;;  teamvault  ;("

const { SENSITIVE_PATHS, isSensitivePath } = await import("../../src/paths.ts")

test("extra paths: valid patterns are appended and match case-insensitively", () => {
    assert.equal(SENSITIVE_PATHS.length, 17, "two valid extras must be appended")
    assert.equal(isSensitivePath("docs/acme-private"), true, "trimmed extra pattern matches")
    assert.equal(isSensitivePath("ACME-PRIVATE"), true, "extra pattern is case-insensitive")
    assert.equal(isSensitivePath("teamvault"), true, "second extra pattern is active")
})

test("extra paths: empty segments contribute no pattern", () => {
    assert.equal(isSensitivePath("src/main.ts"), false, "an empty segment must not make everything sensitive")
})

test("extra paths: an invalid pattern is skipped and logged without leaking it", () => {
    assert.equal(isSensitivePath("("), false, "invalid pattern must not make paths sensitive")
    const raw = readFileSync(LOG, "utf8")
    const records = raw
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))
    const invalid = records.find((r) => r.event === "config.invalid-path")
    assert.ok(invalid, "config.invalid-path record missing")
    assert.equal(invalid.level, "warn", "structured level must be warn")
    assert.equal(invalid.index, 2, "the invalid entry is the third non-empty candidate")
    assert.equal(invalid.error, "invalid-regular-expression")
    assert.equal(invalid.pattern, undefined, "the record must not carry the offending pattern")
    assert.ok(!raw.includes("Invalid regular expression"), "the engine message must not be logged")
})
