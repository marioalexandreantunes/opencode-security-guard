// security-guard record-shape suite (log-schema hygiene): emitted records for
// `loaded`, `project-dir.ready` and `blocked.read` carry exactly the fields
// declared in the typed `LogPayload` registry — no extras, none missing.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/log-record-shape.test.mts

import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-record-shape-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
process.env.SECURITY_GUARD_MODE = "block"

const { SecurityGuard } = await import("../../src/index.ts")
const { bootstrapProjectDir } = await import("../../src/project-dir.ts")
const { getProjectContext, siblingLogPath } = await import("../../src/config.ts")

const project = mkdtempSync(join(tmpdir(), "sg-rs-project-"))

const records = (): any[] => {
    try {
        return readFileSync(LOG, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((l) => JSON.parse(l))
    } catch {
        return []
    }
}
const event = (name: string): any =>
    records()
        .filter((e) => e.event === name)
        .at(-1)
const recordsFrom = (file: string): any[] => {
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

const hooks: any = await SecurityGuard({ client: {}, directory: "/tmp", worktree: "/tmp" })
assert.ok(hooks, "the first root registers its hooks")

test("record shape: loaded carries exactly the documented fields", () => {
    const loaded = event("loaded")
    assert.ok(loaded, "no loaded record")
    assert.deepEqual(
        Object.keys(loaded).sort(),
        ["directory", "event", "level", "log", "logSchema", "mode", "pluginVersion", "ts"],
        "the loaded record must not grow undocumented fields",
    )
    assert.equal(loaded.directory, ".", "the root is sanitized to a dot")
    assert.equal(loaded.level, "info")
    assert.deepEqual(
        Object.keys(loaded),
        ["ts", "level", "logSchema", "pluginVersion", "mode", "directory", "log", "event"],
        "the record keeps controlled fields first and event last for readability",
    )
})

test("record shape: project-dir.ready carries exactly root and log", () => {
    bootstrapProjectDir(mkdtempSync(join(tmpdir(), "sg-rs-root-")))
    const ready = event("project-dir.ready")
    assert.ok(ready, "no project-dir.ready record")
    assert.deepEqual(
        Object.keys(ready).sort(),
        ["event", "level", "log", "root", "ts"],
        "the ready record must not grow undocumented fields",
    )
})

test("record shape: blocked.read carries exactly the alert fields", async () => {
    const projectHooks: any = await SecurityGuard({ client: {}, directory: project, worktree: project })
    await assert.rejects(
        () =>
            projectHooks["tool.execute.before"](
                { tool: "read", sessionID: "s", callID: "c" },
                { args: { filePath: join(project, ".env") } },
            ),
        /read blocked/,
    )
    const projectLog = getProjectContext(realpathSync.native(project))?.logFile
    assert.ok(projectLog, "no captured log for the project root")
    const blocked = recordsFrom(projectLog)
        .filter((e) => e.event === "blocked.read")
        .at(-1)
    assert.ok(blocked, "no blocked.read record")
    assert.deepEqual(
        Object.keys(blocked).sort(),
        ["callID", "event", "file", "level", "sessionID", "tool", "ts"],
        "the blocked.read record must not grow undocumented fields",
    )
    assert.equal(blocked.file, ".env", "a path under the project root is relativized")
})

test("record shape: blocked.write.fullrewrite carries a stable reason", async () => {
    const rewriteProject = mkdtempSync(join(tmpdir(), "sg-rs-rewrite-"))
    const file = join(rewriteProject, "secret-fullrewrite.txt")
    const secret = "AKIA" + "A1B2C3D4E5F6G7H8"
    writeFileSync(file, `api_key=${secret}\n`, "utf8")
    const previous = process.env.SECURITY_GUARD_REHYDRATE
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const projectHooks: any = await SecurityGuard({
            client: {},
            directory: rewriteProject,
            worktree: rewriteProject,
        })
        await assert.rejects(
            () => projectHooks["tool.execute.before"]({ tool: "write" }, { args: { filePath: file, content: "x" } }),
            /cannot reproduce/,
        )
        const projectLog = getProjectContext(realpathSync.native(rewriteProject))?.logFile
        assert.ok(projectLog, "no captured log for the rewrite project")
        const blocked = recordsFrom(projectLog)
            .filter((e) => e.event === "blocked.write.fullrewrite")
            .at(-1)
        assert.ok(blocked, "no blocked.write.fullrewrite record")
        assert.equal(blocked.reason, "contains-secrets")
        assert.ok(blocked.file)
    } finally {
        process.env.SECURITY_GUARD_REHYDRATE = previous
    }
})

test("record shape: halted carries exactly directory and log", async () => {
    const previousProjectDir = process.env.SECURITY_GUARD_PROJECT_DIR
    process.env.SECURITY_GUARD_PROJECT_DIR = "1"
    try {
        const haltedRoot = mkdtempSync(join(tmpdir(), "sg-rs-halted-"))
        mkdirSync(join(haltedRoot, ".security-guard"), { recursive: true })
        writeFileSync(join(haltedRoot, ".security-guard", "halt"), "plugin disabled\n", "utf8")
        const hooks: any = await SecurityGuard({ client: {}, directory: haltedRoot, worktree: haltedRoot })
        assert.deepEqual(hooks, {})
        const haltedLog = siblingLogPath(LOG, realpathSync.native(haltedRoot))
        const halted = recordsFrom(haltedLog)
            .filter((e) => e.event === "halted")
            .at(-1)
        assert.ok(halted, "no halted record")
        assert.deepEqual(
            Object.keys(halted).sort(),
            ["directory", "event", "level", "log", "ts"],
            "the halted record must not grow undocumented fields",
        )
        assert.equal(halted.directory, ".", "the halted root is sanitized to a dot")
    } finally {
        process.env.SECURITY_GUARD_PROJECT_DIR = previousProjectDir
    }
})
