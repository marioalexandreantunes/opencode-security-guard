// security-guard end-to-end fail-closed suite for an uninspectable project
// root: through the real SecurityGuard hooks, a root that cannot be
// canonicalised must block file-tool writes instead of throwing or leaking an
// OS error/absolute path. Synthetic values only.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/unverifiable-root-hook.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-unver-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER, getProjectContext } = await import("../../src/config.ts")

const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const parent = mkdtempSync(join(tmpdir(), "sg-unver-"))
const doomed = join(parent, "missing") // never created: realpath fails

const hooks: any = await SecurityGuard({ client: {}, directory: doomed, worktree: doomed })

const readLog = (): string => {
    try {
        return readFileSync(LOG, "utf8")
    } catch {
        return ""
    }
}

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
