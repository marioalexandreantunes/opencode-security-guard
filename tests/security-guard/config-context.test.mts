// security-guard instance context unit suite: the per-instance log writer,
// sanitizer, guard-log match, deterministic sibling recipe and the live
// registry. Direct pins for the `config.ts` instance seam.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/config-context.test.mts

import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-ctx-log-")), "guard.log")

const cfg = await import("../../src/config.ts")

const root = (): string => mkdtempSync(join(tmpdir(), "sg-ctx-root-"))
const logIn = (dir: string): string => join(dir, "guard.log")

test("context: captures root, canonical root and log file", () => {
    const dir = root()
    const ctx = cfg.createProjectContext({ root: dir, logFile: logIn(dir) })
    assert.equal(ctx.root, dir)
    assert.equal(ctx.canonicalRoot, dir, "the canonical root defaults to the root")
    assert.equal(ctx.logFile, logIn(dir))
    const explicit = cfg.createProjectContext({ root: dir, canonicalRoot: "/canonical", logFile: logIn(dir) })
    assert.equal(explicit.canonicalRoot, "/canonical")
})

test("context: creates a missing parent directory", () => {
    const dir = root()
    const file = join(dir, "missing-parent", "guard.log")
    cfg.createProjectContext({ root: dir, logFile: file })
    assert.ok(existsSync(join(dir, "missing-parent")), "the parent must be created best-effort")
})

test("context: nested missing parents require recursive creation", () => {
    const dir = root()
    const file = join(dir, "a", "b", "guard.log")
    cfg.createProjectContext({ root: dir, logFile: file })
    assert.ok(existsSync(join(dir, "a", "b")), "nested parents need the recursive flag")
})

test("context: the writer appends JSON lines to the captured file", () => {
    const dir = root()
    const ctx = cfg.createProjectContext({ root: dir, logFile: logIn(dir) })
    ctx.writeLog("info", "already-loaded")
    const lines = readFileSync(ctx.logFile, "utf8").trim().split("\n")
    assert.equal(lines.length, 1)
    const record = JSON.parse(lines[0])
    assert.equal(record.event, "already-loaded")
    assert.equal(record.level, "info")
})

test("context: a broken sink warns once on stderr", () => {
    const dir = root()
    const ctx = cfg.createProjectContext({ root: dir, logFile: logIn(dir) })
    rmSync(dir, { recursive: true, force: true })
    const captured: string[] = []
    const original = process.stderr.write
    process.stderr.write = ((chunk: unknown): boolean => {
        captured.push(String(chunk))
        return true
    }) as typeof process.stderr.write
    try {
        ctx.writeLog("info", "already-loaded")
        ctx.writeLog("info", "already-loaded")
    } finally {
        process.stderr.write = original
    }
    assert.equal(captured.length, 1, "exactly one stderr warning per sink")
    assert.match(captured[0], /cannot write log file/)
})

test("context: logPath sanitizes against the captured root", () => {
    const dir = root()
    const ctx = cfg.createProjectContext({ root: dir, logFile: logIn(dir) })
    assert.equal(ctx.logPath(join(dir, "a.txt")), "a.txt")
    assert.equal(ctx.logPath(dir), ".")
    const outside = join(mkdtempSync(join(tmpdir(), "sg-ctx-out-")), "x.txt")
    assert.equal(ctx.logPath(outside), cfg.norm(outside))
})

test("context: isGuardLogPath matches the captured file and rotation", () => {
    const dir = root()
    const ctx = cfg.createProjectContext({ root: dir, logFile: logIn(dir) })
    assert.equal(ctx.isGuardLogPath(logIn(dir)), true)
    assert.equal(ctx.isGuardLogPath(`${logIn(dir)}.1`), true)
    assert.equal(ctx.isGuardLogPath(join(dir, "other.log")), false)
})

test("context: logPathFor pins the lexical guards directly", () => {
    assert.equal(cfg.logPathFor("", "/abs/path.txt"), "/abs/path.txt")
    assert.equal(cfg.logPathFor("/base", ""), "")
    assert.equal(cfg.logPathFor("", ""), "")
    assert.equal(cfg.logPathFor("/base", "relative.txt"), "relative.txt")
    const underCwd = join(process.cwd(), "x.txt")
    assert.equal(cfg.logPathFor("", underCwd), cfg.norm(underCwd), "an empty base never relativizes")
    assert.equal(cfg.logPathFor(process.cwd(), ""), "", "an empty path stays empty")
})

test("context: isGuardLogPathFor rejects prefix lookalikes", () => {
    const file = logIn(root())
    assert.equal(cfg.isGuardLogPathFor(file, file), true)
    assert.equal(cfg.isGuardLogPathFor(file, `${file}.1`), true)
    assert.equal(cfg.isGuardLogPathFor(file, `${file}.1.bak`), false)
    assert.equal(cfg.isGuardLogPathFor(file, `${file}.bak`), false)
    assert.equal(cfg.isGuardLogPathFor("", file), false)
})

test("context: siblingLogPath is a pure deterministic recipe", () => {
    const base = join(tmpdir(), "guard.log")
    const first = cfg.siblingLogPath(base, "/canonical/root")
    const second = cfg.siblingLogPath(base, "/canonical/root")
    assert.equal(first, second, "same inputs must give the same sibling")
    const expected = `guard.${createHash("sha256").update("/canonical/root").digest("hex").slice(0, 16)}.log`
    assert.equal(first, join(tmpdir(), expected))
    assert.notEqual(cfg.siblingLogPath(base, "/other/root"), first, "different roots must differ")
})

test("context: uniqueSiblingLogPath never repeats and keeps the shape", () => {
    const base = join(tmpdir(), "guard.log")
    const a = cfg.uniqueSiblingLogPath(base)
    const b = cfg.uniqueSiblingLogPath(base)
    assert.notEqual(a, b, "each call must be unique")
    assert.ok(a.startsWith(join(tmpdir(), "guard.")), "the stem is preserved")
    assert.ok(a.endsWith(".log"), "the extension is preserved")
    assert.ok(!a.includes("#"), "the token must not collide with the deterministic salt form")
})

test("context: setContextLogFile relocates best-effort", () => {
    const dir = root()
    const ctx = cfg.createProjectContext({ root: dir, logFile: logIn(dir) })
    cfg.setContextLogFile(ctx, "")
    assert.equal(ctx.logFile, logIn(dir), "an empty path is ignored")
    const moved = join(dir, "moved.log")
    cfg.setContextLogFile(ctx, moved)
    assert.equal(ctx.logFile, moved)
    const blocker = join(dir, "blocker")
    writeFileSync(blocker, "not a directory\n")
    cfg.setContextLogFile(ctx, join(blocker, "nested.log"))
    assert.equal(ctx.logFile, moved, "a failed relocation keeps the previous path")
})

test("context: the registry tracks ownership per root", () => {
    const dirA = root()
    const dirB = root()
    const ctxA = cfg.createProjectContext({ root: dirA, logFile: logIn(dirA) })
    const ctxB = cfg.createProjectContext({ root: dirB, logFile: logIn(dirB) })
    try {
        cfg.registerProjectContext(ctxA)
        cfg.registerProjectContext(ctxB)
        assert.equal(cfg.getProjectContext(dirA), ctxA)
        assert.equal(cfg.getProjectContext(dirB), ctxB)
        assert.equal(cfg.getProjectContext(join(tmpdir(), "sg-ctx-unknown")), undefined)
        assert.equal(cfg.isLogPathOwnedByOther(dirB, logIn(dirA)), true)
        assert.equal(cfg.isLogPathOwnedByOther(dirA, logIn(dirA)), false, "a root never collides with itself")
        assert.equal(cfg.isLogPathOwnedByOther(dirB, join(dirB, "fresh.log")), false)
    } finally {
        cfg.releaseProjectContext(dirA)
        cfg.releaseProjectContext(dirB)
    }
    assert.equal(cfg.getProjectContext(dirA), undefined, "release must drop the context")
    assert.equal(cfg.isLogPathOwnedByOther(dirB, logIn(dirA)), false, "release frees the path")
})
