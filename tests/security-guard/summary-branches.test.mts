// Dispose summary branch coverage: counters-only and blocks-only sessions must
// both emit a summary, because either signal is meaningful on its own.
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const { SecurityGuard } = await import("../../src/index.ts")

function events(log: string, name: string): Record<string, unknown>[] {
    try {
        return readFileSync(log, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((line) => JSON.parse(line) as Record<string, unknown>)
            .filter((event) => event.event === name)
    } catch {
        return []
    }
}

async function createHooks(project: string, log: string) {
    const previous = process.env.SECURITY_GUARD_LOG
    process.env.SECURITY_GUARD_LOG = log
    try {
        return await SecurityGuard({ client: {}, directory: project, worktree: project })
    } finally {
        if (previous === undefined) delete process.env.SECURITY_GUARD_LOG
        else process.env.SECURITY_GUARD_LOG = previous
    }
}

test("dispose emits a summary when only counters changed", async () => {
    const project = mkdtempSync(join(tmpdir(), "sg-summary-counters-"))
    const log = join(project, "guard.log")
    const hooks = await createHooks(project, log)
    const output = { parts: [{ type: "text", text: "api_key=Xy9kQ2mN7vR4tW8zB5c" }] }
    await hooks["chat.message"]({}, output)
    await hooks.dispose?.()

    const summary = events(log, "summary").at(-1)
    assert.ok(summary, "counters must emit a summary")
    assert.equal(summary.blocks, 0)
    assert.ok(Object.keys((summary.counters ?? {}) as object).length > 0)
})

test("dispose emits a summary when only blocks changed", async () => {
    const project = mkdtempSync(join(tmpdir(), "sg-summary-blocks-"))
    const log = join(project, "guard.log")
    const hooks = await createHooks(project, log)
    await assert.rejects(() => hooks["tool.execute.before"]({ tool: "bash" }, { args: { command: "env" } }))
    await hooks.dispose?.()

    const summary = events(log, "summary").at(-1)
    assert.ok(summary, "blocks must emit a summary")
    assert.ok(Number(summary.blocks) > 0)
    assert.deepEqual(summary.counters, {})
})
