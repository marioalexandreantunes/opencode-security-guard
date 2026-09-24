// security-guard end-to-end fail-closed suite for an uninspectable project
// root: through the real SecurityGuard hooks, a root that cannot be
// canonicalised must block file-tool writes instead of throwing or leaking an
// OS error/absolute path. Synthetic values only.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/unverifiable-root-hook.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-unver-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
process.env.SECURITY_GUARD_PROJECT_DIR = "0"

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER, getProjectContext } = await import("../../src/config.ts")

const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const parent = mkdtempSync(join(tmpdir(), "sg-unver-"))
const doomed = join(parent, "missing") // never created: realpath fails

const hooks: any = await SecurityGuard({ client: {}, directory: doomed, worktree: doomed })

const readLog = (file = LOG): string => {
    try {
        return readFileSync(file, "utf8")
    } catch {
        return ""
    }
}
const eventCount = (file: string, event: string): number =>
    readLog(file)
        .split(/\r?\n/)
        .filter((line) => line.includes(`"event":"${event}"`)).length

let marker = ""
{
    const output: any = { output: `api_key=${SECRET}`, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "seed", callID: "seed" }, output)
    const m = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(String(output.output))
    assert.ok(m, `no marker minted: ${output.output}`)
    marker = m[0]
}

test("unverifiable root: the instance keeps a null canonical root", () => {
    const ctx = getProjectContext(doomed)
    assert.ok(ctx, "no instance context for the doomed root")
    assert.equal(ctx.canonicalRoot, null, "an uninspectable root must not be replaced by a lexical one")
})

test("unverifiable root: lexical identity deduplicates only the same path", async () => {
    const owner = getProjectContext(doomed)
    assert.ok(owner, "no instance context for the doomed root")
    const before = eventCount(owner.logFile, "already-loaded")

    const duplicate: any = await SecurityGuard({ client: {}, directory: doomed, worktree: doomed })
    assert.deepEqual(duplicate, {})
    assert.equal(getProjectContext(doomed), owner)
    assert.equal(eventCount(owner.logFile, "already-loaded"), before + 1)

    const otherMissing = join(parent, "other-missing")
    const otherHooks: any = await SecurityGuard({ client: {}, directory: otherMissing, worktree: otherMissing })
    assert.ok(Object.keys(otherHooks).length > 0, "a different unresolved root must register independently")
    const otherOwner = getProjectContext(otherMissing)
    assert.ok(otherOwner)
    assert.equal(otherOwner.canonicalRoot, null)
    assert.notEqual(otherOwner, owner)

    const otherBefore = eventCount(otherOwner.logFile, "already-loaded")
    const otherDuplicate: any = await SecurityGuard({ client: {}, directory: otherMissing, worktree: otherMissing })
    assert.deepEqual(otherDuplicate, {})
    assert.equal(eventCount(otherOwner.logFile, "already-loaded"), otherBefore + 1)
    await otherHooks.dispose()
})

test("unverifiable root: a marker write is blocked, not thrown", async () => {
    const args: any = { filePath: join(doomed, "note.txt"), content: `key=${marker}` }
    await assert.rejects(
        () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args }),
        /security-guard:/,
    )
})

test("unverifiable root: a plain write is also blocked (fail closed)", async () => {
    const args: any = { filePath: join(doomed, "plain.txt"), content: "plain text" }
    await assert.rejects(
        () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args }),
        /security-guard:/,
    )
})

test("unverifiable root: diagnostics carry no OS error or absolute path", () => {
    const log = readLog()
    assert.ok(log.includes('"event":"blocked.write"'), "expected a blocked.write record")
    assert.ok(!/ENOENT|EACCES|Error:/.test(log), "an OS/engine message leaked into the log")
    assert.ok(!log.includes(doomed), "the raw absolute doomed path leaked into the log")
})
