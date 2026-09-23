// security-guard plugin import-time env suite: MODE=block (sensitive reads) and
// QUIET=1 (toast suppression). Separate process because config.ts reads both at
// module load.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/plugin-mode-quiet.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-mode-quiet-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
process.env.SECURITY_GUARD_MODE = "block"
process.env.SECURITY_GUARD_QUIET = "1"

const { SecurityGuard } = await import("../../src/index.ts")
const { LOG_FILE, QUIET } = await import("../../src/config.ts")

const project = mkdtempSync(join(tmpdir(), "sg-mq-project-"))

const appLogs: any[] = []
const toasts: any[] = []
const client: any = {
    app: { log: async (i: any) => void appLogs.push(i) },
    tui: { showToast: async (i: any) => void toasts.push(i) },
}
const hooks: any = await SecurityGuard({ client, directory: project, worktree: project })

const readEvents = (): any[] => {
    try {
        return readFileSync(LOG_FILE, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((l) => JSON.parse(l))
    } catch {
        return []
    }
}
const events = (name: string): any[] => readEvents().filter((e) => e.event === name)
const before = (tool: string, args: any) =>
    hooks["tool.execute.before"]({ tool, sessionID: "s", callID: "c" }, { args })

// Order matters: this must be the file's first alert. The toast cooldown (4 s)
// is set by any preceding toast, so running this later would let a broken QUIET
// pass on the cooldown alone — which is exactly how the QUIET mutants survived
// before the direct assert below.
test("QUIET=1: an alert logs but produces no toast", async () => {
    assert.equal(QUIET, true, "QUIET must be read from SECURITY_GUARD_QUIET=1")
    toasts.length = 0
    const secret = ["Qw3Zx9Lm4Nr7Tb2Vp8Kd5", "Ab6Yc1De2Fg3Hi4Jk5Lm6N"].join("")
    const out: any = { parts: [{ type: "text", text: secret }] }
    await hooks["chat.message"]({}, out)
    assert.equal(toasts.length, 0, "QUIET must suppress toasts")
    assert.ok(appLogs.length >= 1, "QUIET must not suppress logging")
    assert.ok(
        String(appLogs.at(-1)?.body?.message).length > 0,
        "the client log message must be present even when quiet",
    )
})

test("MODE=block: a sensitive read is blocked and logged", async () => {
    const n = events("blocked.read").length
    const file = join(project, ".env")
    await assert.rejects(() => before("read", { filePath: file }), /read blocked/)
    const ev = events("blocked.read").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].tool, "read")
    assert.equal(ev[0].file, ".env", "a path under the project root is relativized")
    assert.equal(ev[0].sessionID, "s")
    assert.ok(appLogs.length >= 1)
})

test("MODE=block: a non-sensitive read is allowed", async () => {
    await assert.doesNotReject(() => before("read", { filePath: join(project, "notes.txt") }))
})
