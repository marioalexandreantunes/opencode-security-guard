// security-guard log relocation suite (settable log + dynamic sensitive path).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/log-relocation.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-reloc-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const cfg = await import("../../src/config.ts")
const { isSensitivePath, escapeRe } = await import("../../src/paths.ts")
const { logProbe } = await import("./log-probe.mts")
const probe = logProbe(cfg.writeLog)

const tmpLog = (): string => join(mkdtempSync(join(tmpdir(), "sg-reloc-target-")), "guard.log")

test("log-relocation: the imported log path is sensitive", () => {
    assert.equal(cfg.LOG_FILE, LOG)
    assert.ok(isSensitivePath(LOG))
    assert.ok(isSensitivePath(`${LOG}.1`))
})

test("log-relocation: setLogFile relocates LOG_FILE and logging follows it", () => {
    const moved = tmpLog()
    cfg.setLogFile(moved)
    assert.equal(cfg.LOG_FILE, moved)
    probe("info", "relocation.marker")
    assert.match(readFileSync(moved, "utf8"), /relocation\.marker/)
})

test("log-relocation: isSensitivePath follows the active log and its rotation", () => {
    const first = tmpLog()
    cfg.setLogFile(first)
    assert.ok(isSensitivePath(first), "the active log must be sensitive")
    assert.ok(isSensitivePath(`${first}.1`), "the active rotation must be sensitive")

    const second = tmpLog()
    cfg.setLogFile(second)
    assert.ok(isSensitivePath(second), "the new active log must be sensitive")
    assert.ok(isSensitivePath(`${second}.1`), "the new active rotation must be sensitive")
    assert.ok(!isSensitivePath(first), "the old log path must no longer be special")
})

test("log-relocation: a failed relocation keeps the previous path", () => {
    const good = tmpLog()
    cfg.setLogFile(good)
    const blocker = join(tmpdir(), `sg-reloc-blocker-${process.pid}-${Date.now()}`)
    writeFileSync(blocker, "not a directory\n", "utf8")
    cfg.setLogFile(join(blocker, "nested", "guard.log"))
    assert.equal(cfg.LOG_FILE, good)
})

test("log-relocation: escapeRe escapes regex metacharacters", () => {
    assert.equal(escapeRe("a.b/c (x)"), "a\\.b/c \\(x\\)")
})

test("log-relocation: rotation follows the relocated active log", () => {
    const active = tmpLog()
    cfg.setLogFile(active)
    // Pre-fill the active log beyond the rotation limit, then write one record.
    writeFileSync(active, Buffer.alloc(cfg.LOG_MAX + 1, 0x61))
    probe("info", "rotation.marker")
    assert.ok(existsSync(`${active}.1`), "the active log was not rotated to .1")
    assert.match(readFileSync(active, "utf8"), /rotation\.marker/)
})
