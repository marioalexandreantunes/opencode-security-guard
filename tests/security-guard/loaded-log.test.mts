// security-guard characterization: the `loaded` event is written once per
// registered root, so it needs its own file (the per-root registry makes the
// factory a no-op for an already-registered root).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/loaded-log.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, realpathSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-loaded-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const { MODE, LOG_FILE, PLUGIN_VERSION, getProjectContext, siblingLogPath, norm } = await import("../../src/config.ts")

// A real directory: a literal `/tmp` does not exist on Windows and would make
// the canonical (fail-closed) destination check treat every path as sensitive.
const ROOT = mkdtempSync(join(tmpdir(), "sg-loaded-root-"))

const readEvents = (file: string): any[] =>
    readFileSync(file, "utf8")
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l))

const first = await SecurityGuard({ client: {}, directory: ROOT, worktree: ROOT })

test("characterization: loaded event carries the log schema and plugin version", () => {
    const events = readEvents(LOG)
    const loaded = events.find((e) => e.event === "loaded")
    assert.ok(loaded, "no loaded event")
    assert.equal(loaded.level, "info")
    assert.equal(loaded.logSchema, 11)
    assert.equal(loaded.pluginVersion, PLUGIN_VERSION)
    assert.equal(loaded.version, undefined, "the ambiguous version field must be gone")
    assert.equal(loaded.mode, MODE)
    assert.equal(loaded.directory, ".", "the project root itself is sanitized to a dot")
    assert.equal(loaded.log, norm(LOG_FILE))
    assert.equal(typeof loaded.ts, "string")
})

test("version: PLUGIN_VERSION matches package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"))
    assert.equal(PLUGIN_VERSION, pkg.version)
})

test("characterization: the second factory call logs already-loaded", async () => {
    const again = await SecurityGuard({ client: {}, directory: ROOT })
    assert.deepEqual(again, {})
    assert.match(readFileSync(LOG, "utf8"), /"event":"already-loaded"/)
})

test("lifecycle: a different root registers its own hooks", async () => {
    const other = mkdtempSync(join(tmpdir(), "sg-other-root-"))
    const hooks = await SecurityGuard({ client: {}, directory: other, worktree: other })
    assert.equal(
        typeof (hooks as { dispose?: unknown }).dispose,
        "function",
        "the second root registers a full hook set",
    )
    const otherLog = getProjectContext(other)?.logFile
    assert.equal(
        otherLog,
        siblingLogPath(LOG, realpathSync.native(other)),
        "the second root receives the deterministic sibling log",
    )
    assert.ok(otherLog, "no captured log for the second root")
    const loaded = readEvents(otherLog).filter((e) => e.event === "loaded")
    assert.equal(loaded.length, 1, "the second root writes its own loaded event to its own log")
    assert.equal(loaded[0].directory, ".", "the second root is also sanitized to a dot")
    await (hooks as { dispose: () => Promise<void> }).dispose()
})

test("lifecycle: dispose releases the root, so the same root can register again", async () => {
    await first.dispose()
    const reloaded = await SecurityGuard({ client: {}, directory: ROOT })
    assert.equal(typeof (reloaded as { dispose?: unknown }).dispose, "function", "the disposed root registers again")
    const loaded = readEvents(LOG).filter((e) => e.event === "loaded")
    assert.equal(loaded.length, 2, "a new loaded event for the released root")
    assert.equal(loaded[1].directory, ".", "the re-registered root is sanitized to a dot")
    await (reloaded as { dispose: () => Promise<void> }).dispose()
})
