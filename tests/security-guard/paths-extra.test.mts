// SECURITY_GUARD_EXTRA_PATHS literal matching coverage.
// The variable must be set before `paths.ts` is imported (its own process).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/paths-extra.test.mts

import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-extra-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
// padded literal terms, `;` separators, empty segments, and regex-looking text.
process.env.SECURITY_GUARD_EXTRA_PATHS = "  acme-private  ;;  teamvault  ;(a+)+$"

const { SENSITIVE_PATHS, isSensitivePath } = await import("../../src/paths.ts")

test("extra paths: literal terms are appended and match case-insensitively", () => {
    assert.equal(SENSITIVE_PATHS.length, 18, "three literal extras must be appended")
    assert.equal(isSensitivePath("docs/acme-private"), true, "trimmed extra term matches")
    assert.equal(isSensitivePath("ACME-PRIVATE"), true, "extra term is case-insensitive")
    assert.equal(isSensitivePath("teamvault"), true, "second extra term is active")
})

test("extra paths: empty segments contribute no pattern", () => {
    assert.equal(isSensitivePath("src/main.ts"), false, "an empty segment must not make everything sensitive")
})

test("extra paths: regex-looking terms match only literal metacharacters", () => {
    assert.equal(isSensitivePath("docs/(a+)+$"), true, "metacharacters must match literally")
    assert.equal(isSensitivePath("docs/aaaaaaaaaaaaaaaa!"), false, "regex expansion must not occur")
})

test("extra paths: adversarial literal stays bounded in an isolated process", () => {
    const child = spawnSync(
        process.execPath,
        [
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            `
                process.env.SECURITY_GUARD_PROJECT_DIR = "0"
                process.env.SECURITY_GUARD_EXTRA_PATHS = "^(a+)+$"
                const { isSensitivePath } = await import("./src/paths.ts")
                const literal = isSensitivePath("docs/^(a+)+$")
                const longInput = isSensitivePath("a".repeat(20000) + "!")
                if (!literal || longInput) {
                    console.error("extra-path regression failed")
                    process.exitCode = 1
                }
            `,
        ],
        { cwd: process.cwd(), env: { ...process.env }, encoding: "utf8", timeout: 5000 },
    )
    assert.ok(!child.error, "extra-path child timed out or failed to spawn")
    assert.equal(child.status, 0, "extra-path regression failed")
})
