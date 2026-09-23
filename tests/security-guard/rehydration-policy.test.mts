// security-guard rehydration destination policy (C2).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/rehydration-policy.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { linkDir } from "./platform-fixtures.mts"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-policy-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER, LOG_FILE } = await import("../../src/config.ts")

const project = mkdtempSync(join(tmpdir(), "sg-project-"))
const inside = join(project, "inside.txt")
const outside = join(project, "..", "sg-outside.txt")

const hooks = await SecurityGuard({ client: {}, directory: project, worktree: project })

const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const CRED = `api_key=${SECRET}`

async function seed(): Promise<string> {
    const output: any = { output: CRED, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, output)
    const m = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(String(output.output))
    assert.ok(m, `no marker produced: ${output.output}`)
    return m[0]
}
const marker = await seed()

test("C2: a known marker inside the worktree is rehydrated", async () => {
    const args: any = { filePath: inside, content: CRED.replace(SECRET, marker) }
    await hooks["tool.execute.before"]({ tool: "write" }, { args })
    assert.ok(args.content.includes(SECRET), `content not rehydrated: ${args.content}`)
})

test("C2: a write without markers outside the worktree is allowed", async () => {
    const args: any = { filePath: outside, content: "plain text" }
    await hooks["tool.execute.before"]({ tool: "write" }, { args })
    assert.equal(args.content, "plain text")
})

test("C2: a known marker outside the worktree is blocked by default", async () => {
    const args: any = { filePath: outside, content: CRED.replace(SECRET, marker) }
    await assert.rejects(() => hooks["tool.execute.before"]({ tool: "write" }, { args }), /outside the project/)
})

test("C2: the external opt-in allows the write and logs a warning", async () => {
    const count = () => (readFileSync(LOG_FILE, "utf8").match(/"event":"rehydrated\.external"/g) ?? []).length
    const before = count()
    process.env.SECURITY_GUARD_REHYDRATE_EXTERNAL = "1"
    try {
        const args: any = { filePath: outside, content: CRED.replace(SECRET, marker) }
        await hooks["tool.execute.before"]({ tool: "write" }, { args })
        assert.ok(args.content.includes(SECRET), "content not rehydrated")
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE_EXTERNAL
    }
    assert.equal(count() - before, 1, "expected one rehydrated.external warning")
})

test("C2: a patch destination reached through a link is blocked", async () => {
    const linkedOut = join(project, "linked-out")
    linkDir(mkdtempSync(join(tmpdir(), "sg-policy-ext-")), linkedOut)
    const target = join(linkedOut, "new.txt")
    const args: any = { patchText: `*** Add File: ${target}\n+${CRED.replace(SECRET, marker)}\n` }
    await assert.rejects(() => hooks["tool.execute.before"]({ tool: "apply_patch" }, { args }), /outside the project/)
})

test("C2: bash rehydration is exempt from the worktree policy", async () => {
    process.env.SECURITY_GUARD_REHYDRATE_BASH = "1"
    try {
        const args: any = { command: `echo '${marker}' > ${outside}` }
        await hooks["tool.execute.before"]({ tool: "bash" }, { args })
        assert.ok(args.command.includes(SECRET), `bash command not rehydrated: ${args.command}`)
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE_BASH
    }
})
