// security-guard config defaults + writeLog behaviour
// (strengthen-config-mutation-tests). Clean env: config.ts reads env once at
// import, and this file runs in its own process.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/config-defaults.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

delete process.env.SECURITY_GUARD_LOG
delete process.env.SECURITY_GUARD_MODE
delete process.env.SECURITY_GUARD_QUIET
delete process.env.SECURITY_GUARD_LOG_LEVEL

const cfg = await import("../../src/config.ts")
const { logProbe } = await import("./log-probe.mts")
const probe = logProbe(cfg.writeLog)

const tmpLog = (): string => join(mkdtempSync(join(tmpdir(), "sg-cfg-")), "guard.log")

test("defaults: MODE falls back to redact", () => {
    assert.equal(cfg.MODE, "redact")
})

test("defaults: LOG_FILE is the tmp fallback until the bootstrap relocates it", () => {
    const expected = join(tmpdir(), "opencode-security-guard.log").replace(/\\/g, "/")
    assert.equal(cfg.LOG_FILE.replace(/\\/g, "/"), expected)
})

test("defaults: LOG_MAX is 5 MiB", () => {
    assert.equal(cfg.LOG_MAX, 5 * 1024 * 1024)
})

test("logAllows: default level matrix", () => {
    assert.equal(cfg.logAllows("debug"), false, "debug is below the default info minimum")
    assert.equal(cfg.logAllows("info"), true)
    assert.equal(cfg.logAllows("error"), true)
    assert.equal(cfg.logAllows("trace"), true, "an unknown level falls back to the info rank")
})

test("norm: nullish inputs normalise to an empty string", () => {
    assert.equal(cfg.norm(null), "")
    assert.equal(cfg.norm(undefined), "")
})

test("writeLog: the level filter drops records below the minimum", () => {
    const log = tmpLog()
    cfg.setLogFile(log)
    probe("debug", "filtered.marker")
    assert.equal(existsSync(log), false, "a filtered record must not create the log")
    probe("info", "kept.marker")
    const body = readFileSync(log, "utf8")
    assert.match(body, /kept\.marker/)
    assert.doesNotMatch(body, /filtered\.marker/)
})

test("setLogFile: an empty path is ignored and logging follows the previous file", () => {
    const log = tmpLog()
    cfg.setLogFile(log)
    cfg.setLogFile("")
    assert.equal(cfg.LOG_FILE, log, "an empty path must not relocate the log")
    probe("info", "after-empty.marker")
    assert.match(readFileSync(log, "utf8"), /after-empty\.marker/)
})

test("rotation: a file at exactly LOG_MAX bytes is not rotated", () => {
    const log = tmpLog()
    cfg.setLogFile(log)
    writeFileSync(log, Buffer.alloc(cfg.LOG_MAX, 0x61))
    probe("info", "boundary.marker")
    assert.equal(existsSync(`${log}.1`), false, "the rotation threshold is strict (>)")
    assert.match(readFileSync(log, "utf8"), /boundary\.marker/)
})

// Runs last: it leaves `logFailureWarned` set for the rest of the process.
test("writeLog: a broken log warns exactly once", () => {
    const dir = mkdtempSync(join(tmpdir(), "sg-cfg-broken-"))
    const log = join(dir, "guard.log")
    cfg.setLogFile(log)
    rmSync(dir, { recursive: true, force: true })

    const captured: string[] = []
    const original = process.stderr.write
    process.stderr.write = ((chunk: string | Uint8Array) => {
        captured.push(String(chunk))
        return true
    }) as typeof process.stderr.write
    try {
        probe("info", "fail.one")
        probe("info", "fail.two")
    } finally {
        process.stderr.write = original
    }

    assert.equal(captured.length, 1, "exactly one warning must be emitted")
    assert.match(captured[0], /cannot write log/)
    assert.ok(!captured[0].includes(log), "the warning must not interpolate the raw log path")

    cfg.setLogFile(tmpLog())
})
