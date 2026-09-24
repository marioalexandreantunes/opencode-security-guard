// security-guard halt kill-switch suite: `.security-guard/halt` existing
// disables the guard for that project (presence only), and removing it
// re-enables on the next load. `SECURITY_GUARD_PROJECT_DIR=0` ignores the file.
// Each factory load uses its own explicit log: instance logs are never shared,
// so every load below points `SECURITY_GUARD_LOG` at a fresh file first.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/halt.test.mts

import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOGDIR = mkdtempSync(join(tmpdir(), "sg-halt-log-"))
let logCounter = 0
const newLog = (): string => {
    const file = join(LOGDIR, `guard-${logCounter++}.log`)
    process.env.SECURITY_GUARD_LOG = file
    return file
}
process.env.SECURITY_GUARD_PROJECT_DIR = "1"

const { SecurityGuard } = await import("../../src/index.ts")
const { SECURITY_GUARD_DIR } = await import("../../src/project-dir.ts")
const { getProjectContext, norm } = await import("../../src/config.ts")

const ROOTS = mkdtempSync(join(tmpdir(), "sg-halt-"))
let counter = 0
const newRoot = (): string => {
    const root = join(ROOTS, `root-${counter++}`)
    mkdirSync(root, { recursive: true })
    return root
}
const events = (log: string): any[] => {
    try {
        return readFileSync(log, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((l) => JSON.parse(l))
    } catch {
        return []
    }
}

const rootWithHalt = (): string => {
    const root = newRoot()
    const dir = join(root, SECURITY_GUARD_DIR)
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, "halt"), "plugin disabled\n", "utf8")
    return root
}

test("halt: a .security-guard/halt file disables the guard for that project", async () => {
    const root = rootWithHalt()
    const log = newLog()
    const hooks = await SecurityGuard({ client: {}, directory: root, worktree: root })
    assert.deepEqual(hooks, {}, "the halted factory must register no hooks")
    const all = events(log)
    const halted = all.find((e) => e.event === "halted")
    assert.ok(halted, "a halted event must be logged")
    assert.equal(halted.directory, ".")
    assert.equal(halted.log, norm(log), "the halted record identifies its own log")
    assert.ok(!all.some((e) => e.event === "loaded"), "no loaded event for a halted root")
})

test("halt: removing the file re-enables the guard on the next load", async () => {
    const root = rootWithHalt()
    newLog()
    await SecurityGuard({ client: {}, directory: root, worktree: root })
    rmSync(join(root, SECURITY_GUARD_DIR, "halt"))
    const log = newLog()
    const hooks = await SecurityGuard({ client: {}, directory: root, worktree: root })
    assert.equal(
        typeof (hooks as { dispose?: unknown }).dispose,
        "function",
        "the root registers after the halt is gone",
    )
    assert.ok(
        events(log).some((e) => e.event === "loaded"),
        "a loaded event after removing the halt file",
    )
    await (hooks as { dispose: () => Promise<void> }).dispose()
})

test("halt: a disposed instance observes the sentinel on the next load", async () => {
    const root = newRoot()
    newLog()
    const active = await SecurityGuard({ client: {}, directory: root, worktree: root })
    assert.equal(typeof (active as { dispose?: unknown }).dispose, "function")
    await (active as { dispose: () => Promise<void> }).dispose()

    writeFileSync(join(root, SECURITY_GUARD_DIR, "halt"), "plugin disabled\n", "utf8")
    newLog()
    const halted = await SecurityGuard({ client: {}, directory: root, worktree: root })
    assert.deepEqual(halted, {})

    rmSync(join(root, SECURITY_GUARD_DIR, "halt"))
    const log = newLog()
    const reloaded = await SecurityGuard({ client: {}, directory: root, worktree: root })
    assert.equal(typeof (reloaded as { dispose?: unknown }).dispose, "function")
    assert.ok(
        events(log).some((e) => e.event === "loaded"),
        "a loaded event after the halt is gone",
    )
    await (reloaded as { dispose: () => Promise<void> }).dispose()
})

test("halt: SECURITY_GUARD_PROJECT_DIR=0 ignores the halt file", async () => {
    process.env.SECURITY_GUARD_PROJECT_DIR = "0"
    try {
        const root = rootWithHalt()
        const log = newLog()
        const hooks = await SecurityGuard({ client: {}, directory: root, worktree: root })
        assert.equal(typeof (hooks as { dispose?: unknown }).dispose, "function")
        assert.ok(
            events(log).some((e) => e.event === "loaded"),
            "the guard loads despite the halt file",
        )
        assert.equal(
            getProjectContext(realpathSync.native(root))?.logFile,
            log,
            "the registered instance exposes its captured log",
        )
        await (hooks as { dispose: () => Promise<void> }).dispose()
    } finally {
        process.env.SECURITY_GUARD_PROJECT_DIR = "1"
    }
})

test("halt: a worktree sentinel halts the project regardless of the current directory", async () => {
    const worktree = newRoot()
    const current = join(worktree, "current")
    mkdirSync(current, { recursive: true })
    mkdirSync(join(worktree, SECURITY_GUARD_DIR), { recursive: true })
    writeFileSync(join(worktree, SECURITY_GUARD_DIR, "halt"), "plugin disabled\n", "utf8")

    newLog()
    const hooks = await SecurityGuard({ client: {}, directory: current, worktree })
    assert.deepEqual(hooks, {}, "the worktree sentinel must halt the instance")
})

test("halt: an active instance ignores a newly created sentinel", async () => {
    const root = newRoot()
    const log = newLog()
    const active = await SecurityGuard({ client: {}, directory: root, worktree: root })
    assert.equal(typeof (active as { dispose?: unknown }).dispose, "function")
    const haltedBefore = events(log).filter((e) => e.event === "halted").length
    writeFileSync(join(root, SECURITY_GUARD_DIR, "halt"), "plugin disabled\n", "utf8")

    const again = await SecurityGuard({ client: {}, directory: root, worktree: root })
    assert.deepEqual(again, {})
    const all = events(log)
    assert.ok(
        all.some((e) => e.event === "already-loaded"),
        "the duplicate call must log already-loaded",
    )
    assert.equal(
        all.filter((e) => e.event === "halted").length,
        haltedBefore,
        "an active instance must not halt mid-session",
    )
    assert.equal(
        getProjectContext(realpathSync.native(root))?.logFile,
        log,
        "the registered instance exposes its captured log",
    )
    await (active as { dispose: () => Promise<void> }).dispose()
})
