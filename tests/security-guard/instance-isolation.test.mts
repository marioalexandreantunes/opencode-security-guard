// security-guard instance isolation suite: two live project roots work
// simultaneously with independent logs, sanitization bases, sensitive-log
// policies, blacklist loggers and project-directory loggers. Synthetic temp
// fixtures only.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/instance-isolation.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { linkDir } from "./platform-fixtures.mts"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-iso-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
process.env.SECURITY_GUARD_PROJECT_DIR = "1"
process.env.SECURITY_GUARD_BLACKLIST_TTL_MS = "0"

const { SecurityGuard } = await import("../../src/index.ts")
const {
    MARKER,
    createProjectContext,
    getProjectContext,
    registerProjectContext,
    releaseProjectContext,
    siblingLogPath,
    norm,
} = await import("../../src/config.ts")
const identityForRoot = (root: string): string => realpathSync.native(root)

const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const CRED = `api_key=${SECRET}`
const TERM_A = "ZetaGadget4242"

const rootA = mkdtempSync(join(tmpdir(), "sg-iso-a-"))
const rootB = mkdtempSync(join(tmpdir(), "sg-iso-b-"))

const hooksA: any = await SecurityGuard({ client: {}, directory: rootA, worktree: rootA })
const hooksB: any = await SecurityGuard({ client: {}, directory: rootB, worktree: rootB })

const sibB = siblingLogPath(LOG, realpathSync.native(rootB))

const readLog = (file: string): any[] => {
    try {
        return readFileSync(file, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((l) => JSON.parse(l))
    } catch {
        return []
    }
}
const sessions = (file: string, event: string): unknown[] =>
    readLog(file)
        .filter((e) => e.event === event)
        .map((e) => e.sessionID)
const count = (file: string, event: string): number => readLog(file).filter((e) => e.event === event).length

test("isolation: each root captures its own log destination", () => {
    assert.equal(
        getProjectContext(identityForRoot(rootA))?.logFile,
        LOG,
        "the first root keeps the exact explicit path",
    )
    assert.equal(
        getProjectContext(identityForRoot(rootB))?.logFile,
        sibB,
        "the second root receives the deterministic sibling",
    )
    assert.notEqual(LOG, sibB)
})

test("isolation: redaction events stay in the owning log", async () => {
    const outA: any = { output: CRED, metadata: {} }
    await hooksA["tool.execute.after"]({ tool: "bash", sessionID: "sess-A", callID: "a" }, outA)
    const outB: any = { output: CRED, metadata: {} }
    await hooksB["tool.execute.after"]({ tool: "bash", sessionID: "sess-B", callID: "b" }, outB)
    assert.ok(sessions(LOG, "redacted.tool").includes("sess-A"))
    assert.ok(!sessions(LOG, "redacted.tool").includes("sess-B"), "B's event leaked into A's log")
    assert.ok(sessions(sibB, "redacted.tool").includes("sess-B"))
    assert.ok(!sessions(sibB, "redacted.tool").includes("sess-A"), "A's event leaked into B's log")
})

test("isolation: each root sanitizes paths against its own base", async () => {
    const target = join(rootA, "sub", ".env")
    const nA = count(LOG, "blocked.write")
    const nB = count(sibB, "blocked.write")
    await assert.rejects(() =>
        hooksA["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args: { filePath: target } }),
    )
    await assert.rejects(() =>
        hooksB["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args: { filePath: target } }),
    )
    // The earlier instance still uses its own base after the later root loaded.
    await assert.rejects(() =>
        hooksA["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args: { filePath: target } }),
    )
    const filesA = readLog(LOG)
        .filter((e) => e.event === "blocked.write")
        .slice(nA)
        .map((e) => e.file)
    assert.deepEqual(filesA, ["sub/.env", "sub/.env"], "A must keep A-relative paths")
    const filesB = readLog(sibB)
        .filter((e) => e.event === "blocked.write")
        .slice(nB)
        .map((e) => e.file)
    assert.equal(filesB.length, 1)
    assert.ok(filesB[0] !== "sub/.env", "B must not relativize against A's root")
    assert.ok(String(filesB[0]).includes("sub/.env"), "B keeps the absolute external path")
})

test("isolation: blacklist events belong to the owning instance", async () => {
    writeFileSync(join(rootA, ".security-guard", "blacklist"), `# team\n${TERM_A}\n`)
    const outA: any = { output: `uses ${TERM_A} here`, metadata: {} }
    await hooksA["tool.execute.after"]({ tool: "bash", sessionID: "sess-A-bl", callID: "a" }, outA)
    assert.ok(!String(outA.output).includes(TERM_A), "the team term was not redacted")
    const outB: any = { output: `uses ${TERM_A} here`, metadata: {} }
    await hooksB["tool.execute.after"]({ tool: "bash", sessionID: "sess-B-bl", callID: "b" }, outB)
    assert.equal(String(outB.output), `uses ${TERM_A} here`, "B has no such term and must stay inert")
    assert.ok(sessions(LOG, "redacted.tool").includes("sess-A-bl"))
    assert.ok(!sessions(sibB, "redacted.tool").includes("sess-B-bl"), "an inert instance logs nothing")
    assert.ok(!readFileSync(LOG, "utf8").includes(TERM_A), "the raw team term leaked into A's log")
})

test("isolation: project-directory events belong to the owning instance", () => {
    for (const file of [LOG, sibB]) {
        const ready = readLog(file).filter((e) => e.event === "project-dir.ready")
        assert.ok(ready.length >= 1, `no project-dir.ready in ${file}`)
        assert.equal(ready.at(-1).root, ".", "each instance logs its own root as a dot")
    }
    assert.equal(
        readLog(LOG)
            .filter((e) => e.event === "project-dir.ready")
            .at(-1).log,
        norm(LOG),
    )
    assert.equal(
        readLog(sibB)
            .filter((e) => e.event === "project-dir.ready")
            .at(-1).log,
        norm(sibB),
    )
})

test("isolation: already-loaded resolves the owning context", async () => {
    const nA = count(LOG, "already-loaded")
    const nB = count(sibB, "already-loaded")
    const again: any = await SecurityGuard({ client: {}, directory: rootA, worktree: rootA })
    assert.deepEqual(again, {})
    assert.equal(count(LOG, "already-loaded"), nA + 1)
    assert.equal(count(sibB, "already-loaded"), nB, "already-loaded leaked into the other log")
})

test("isolation: canonical aliases share one owner in either load order", async () => {
    for (const firstIsAlias of [false, true]) {
        const target = mkdtempSync(join(tmpdir(), "sg-iso-alias-target-"))
        const alias = join(mkdtempSync(join(tmpdir(), "sg-iso-alias-parent-")), "project")
        linkDir(target, alias)

        const firstRoot = firstIsAlias ? alias : target
        const alternateRoot = firstIsAlias ? target : alias
        const identityKey = identityForRoot(target)
        const firstHooks: any = await SecurityGuard({ client: {}, directory: firstRoot, worktree: firstRoot })
        const owner = getProjectContext(identityKey)
        assert.ok(owner, "the first path must register the canonical identity")
        assert.equal(owner.root, firstRoot, "the first path remains the operational root")

        const before = count(owner.logFile, "already-loaded")
        const duplicate: any = await SecurityGuard({ client: {}, directory: alternateRoot, worktree: alternateRoot })
        assert.deepEqual(duplicate, {})
        assert.equal(getProjectContext(identityKey), owner, "the alias must resolve to the original owner")
        assert.equal(count(owner.logFile, "already-loaded"), before + 1, "the duplicate is logged by the owner")

        await firstHooks.dispose()
        assert.equal(getProjectContext(identityKey), undefined, "dispose releases the canonical identity")

        const reloaded: any = await SecurityGuard({ client: {}, directory: alternateRoot, worktree: alternateRoot })
        assert.ok(Object.keys(reloaded).length > 0, "an alias can register after the owner is disposed")
        assert.equal(getProjectContext(identityKey)?.root, alternateRoot)
        await reloaded.dispose()
    }
})

test("isolation: disposing one root leaves the other untouched", async () => {
    await hooksB.dispose()
    assert.equal(getProjectContext(identityForRoot(rootB)), undefined, "the disposed context must be released")
    assert.ok(getProjectContext(identityForRoot(rootA)), "the remaining context must survive")
    const target = join(rootA, "sub", ".env")
    const nA = count(LOG, "blocked.write")
    await assert.rejects(() =>
        hooksA["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args: { filePath: target } }),
    )
    const ev = readLog(LOG)
        .filter((e) => e.event === "blocked.write")
        .slice(nA)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].file, "sub/.env", "the survivor keeps its original base")
})

test("isolation: the collision rule also applies with the bootstrap disabled", async () => {
    process.env.SECURITY_GUARD_PROJECT_DIR = "0"
    try {
        const rootC = mkdtempSync(join(tmpdir(), "sg-iso-c-"))
        const hooksC: any = await SecurityGuard({ client: {}, directory: rootC, worktree: rootC })
        const sibC = siblingLogPath(LOG, realpathSync.native(rootC))
        assert.equal(getProjectContext(identityForRoot(rootC))?.logFile, sibC)
        const outC: any = { output: CRED, metadata: {} }
        await hooksC["tool.execute.after"]({ tool: "bash", sessionID: "sess-C", callID: "c" }, outC)
        assert.ok(sessions(sibC, "redacted.tool").includes("sess-C"))
        assert.ok(!sessions(LOG, "redacted.tool").includes("sess-C"), "C's event leaked into A's log")
        await hooksC.dispose()
    } finally {
        process.env.SECURITY_GUARD_PROJECT_DIR = "1"
    }
})

test("isolation: many aliases share one canonical owner and log sink", async () => {
    const prevLog = process.env.SECURITY_GUARD_LOG
    const prevDir = process.env.SECURITY_GUARD_PROJECT_DIR
    const logDir = mkdtempSync(join(tmpdir(), "sg-exhaust-log-"))
    process.env.SECURITY_GUARD_LOG = join(logDir, "guard.log")
    process.env.SECURITY_GUARD_PROJECT_DIR = "0"
    const target = mkdtempSync(join(tmpdir(), "sg-exhaust-target-"))
    let ownerHooks: any
    try {
        ownerHooks = await SecurityGuard({ client: {}, directory: target, worktree: target })
        const identityKey = identityForRoot(target)
        const owner = getProjectContext(identityKey)
        assert.ok(owner, "the canonical root must register one owner")
        const before = count(owner.logFile, "already-loaded")

        for (let i = 0; i < 19; i++) {
            const alias = join(mkdtempSync(join(tmpdir(), "sg-exhaust-alias-")), `link-${i}`)
            linkDir(target, alias)
            const duplicate: any = await SecurityGuard({ client: {}, directory: alias, worktree: alias })
            assert.deepEqual(duplicate, {}, `alias ${i} must not create another hook set`)
        }
        assert.equal(getProjectContext(identityKey), owner, "all aliases must share the original owner")
        assert.equal(count(owner.logFile, "already-loaded"), before + 19, "all duplicates use the owner's sink")
    } finally {
        await ownerHooks?.dispose?.()
        if (prevLog === undefined) delete process.env.SECURITY_GUARD_LOG
        else process.env.SECURITY_GUARD_LOG = prevLog
        if (prevDir === undefined) delete process.env.SECURITY_GUARD_PROJECT_DIR
        else process.env.SECURITY_GUARD_PROJECT_DIR = prevDir
    }
})

test("isolation: log collision retries compare canonical identity keys", async () => {
    const prevLog = process.env.SECURITY_GUARD_LOG
    const prevDir = process.env.SECURITY_GUARD_PROJECT_DIR
    const logDir = mkdtempSync(join(tmpdir(), "sg-identity-collision-log-"))
    const baseLog = join(logDir, "guard.log")
    process.env.SECURITY_GUARD_LOG = baseLog
    process.env.SECURITY_GUARD_PROJECT_DIR = "0"

    const target = mkdtempSync(join(tmpdir(), "sg-identity-collision-target-"))
    const alias = join(mkdtempSync(join(tmpdir(), "sg-identity-collision-alias-")), "project")
    linkDir(target, alias)
    const identityKey = identityForRoot(target)
    const firstSibling = siblingLogPath(baseLog, identityKey)
    const aliasKeyOwner = createProjectContext({ root: alias, canonicalRoot: identityKey, logFile: firstSibling })
    const baseLogOwner = createProjectContext({
        root: mkdtempSync(join(tmpdir(), "sg-identity-collision-owner-")),
        logFile: baseLog,
    })
    const baseLogOwnerKey = `${identityKey}#base-log-owner`
    let hooks: any

    try {
        registerProjectContext(alias, aliasKeyOwner)
        registerProjectContext(baseLogOwnerKey, baseLogOwner)

        hooks = await SecurityGuard({ client: {}, directory: alias, worktree: alias })

        const instance = getProjectContext(identityKey)
        assert.ok(instance, "the alias load must register by canonical identity")
        assert.equal(
            instance.logFile,
            siblingLogPath(baseLog, `${identityKey}#1`),
            "a sibling already owned under the lexical key must be skipped",
        )
        assert.notEqual(instance.logFile, aliasKeyOwner.logFile, "distinct identities must not share a log sink")
    } finally {
        await hooks?.dispose?.()
        releaseProjectContext(identityKey)
        releaseProjectContext(alias)
        releaseProjectContext(baseLogOwnerKey)
        if (prevLog === undefined) delete process.env.SECURITY_GUARD_LOG
        else process.env.SECURITY_GUARD_LOG = prevLog
        if (prevDir === undefined) delete process.env.SECURITY_GUARD_PROJECT_DIR
        else process.env.SECURITY_GUARD_PROJECT_DIR = prevDir
    }
})

test("isolation: markers minted by one instance rehydrate in its own root", async () => {
    const out: any = { output: CRED, metadata: {} }
    await hooksA["tool.execute.after"]({ tool: "bash", sessionID: "seed", callID: "seed" }, out)
    const m = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(String(out.output))
    assert.ok(m, `no marker minted: ${out.output}`)
    const args: any = { filePath: join(rootA, "note.txt"), content: `key=${m[0]}` }
    await hooksA["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args })
    assert.ok(String(args.content).includes(SECRET), "the marker did not rehydrate in its own root")
    await hooksA.dispose()
})
