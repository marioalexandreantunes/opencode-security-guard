// security-guard plugin chat/alert/dispose suite: chat-hook log events and dedup,
// structural-field preservation, alert delivery paths (controlled clock) and the
// dispose summary.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/plugin-chat-dispose.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-chat-dispose-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER, LOG_FILE, TOAST_COOLDOWN_MS } = await import("../../src/config.ts")

const project = mkdtempSync(join(tmpdir(), "sg-cd-project-"))

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

/** Fresh detectable secret so each alert is novel (dedup never suppresses it). */
let seq = 0
const novel = (): string => `api_key=Xy9kQ2mN7vR4tW8zB5c${(seq++).toString(16).padStart(2, "0")}`
const beforeHook = (tool: string, args: any) =>
    hooks["tool.execute.before"]({ tool, sessionID: "s", callID: "c" }, { args })
const rehydrateThrough = async (marker: string): Promise<any> => {
    const args: any = { filePath: join(project, "rehydrate.txt"), content: marker }
    await beforeHook("write", args)
    return args
}
const triggerPrompt = async (): Promise<void> => {
    const out: any = { parts: [{ type: "text", text: novel() }] }
    await hooks["chat.message"]({}, out)
}

// Controlled clock: the toast cooldown is per plugin instance and reads Date.now()
// at call time, so we drive it to observe each toast branch deterministically.
const realNow = Date.now
let now = realNow()
Date.now = () => now
const advance = (): void => {
    now += TOAST_COOLDOWN_MS + 1
}

// ── dispose: quiet first (counters are still empty here) ──────────────────
test("dispose: a quiet session writes no summary", async () => {
    const n = events("summary").length
    await hooks.dispose()
    assert.equal(events("summary").length, n)
})

// ── structural-field preservation ─────────────────────────────────────────
test("chat.message preserves every PART_SKIP field", async () => {
    const v = novel()
    const part: any = { text: "ok" }
    const keys = ["id", "sessionID", "messageID", "type", "callID", "time", "tokens"]
    for (const k of keys) part[k] = v
    const out: any = { parts: [part] }
    await hooks["chat.message"]({}, out)
    for (const k of keys) assert.equal(out.parts[0][k], v, `${k} must be preserved`)
})

test("chat.message preserves every INFO_SKIP field and redacts the rest", async () => {
    const v = novel()
    const keys = [
        "id",
        "sessionID",
        "parentID",
        "messageID",
        "modelID",
        "providerID",
        "agent",
        "role",
        "mode",
        "finish",
        "type",
        "callID",
        "time",
        "tokens",
        "cost",
    ]
    const message: any = { system: v }
    for (const k of keys) message[k] = v
    const out: any = { message }
    await hooks["chat.message"]({}, out)
    for (const k of keys) assert.equal(out.message[k], v, `${k} must be preserved`)
    assert.ok(!out.message.system.includes(v), "a non-skipped field must be redacted")
    assert.ok(out.message.system.includes(MARKER))
})

// ── chat hooks: defensive shapes and clean inputs ─────────────────────────
test("chat hooks: empty outputs are handled without throwing", async () => {
    await hooks["chat.message"]({}, {})
    await hooks["chat.message"]({}, { parts: [] })
    await hooks["chat.message"]({}, undefined)
    await hooks["experimental.chat.messages.transform"]({}, {})
    await hooks["experimental.chat.messages.transform"]({}, undefined)
    await hooks["experimental.chat.messages.transform"]({}, { messages: [{ parts: [] }, undefined] })
    const out: any = {}
    await hooks["experimental.chat.system.transform"]({}, out)
    assert.ok(Array.isArray(out.system))
})

test("chat.message: a clean prompt logs no redacted.prompt", async () => {
    const n = events("redacted.prompt").length
    await hooks["chat.message"]({}, { parts: [{ type: "text", text: "nothing sensitive here" }] })
    assert.equal(events("redacted.prompt").length, n)
})

// ── chat hooks: log events, payloads and dedup ────────────────────────────
test("chat.message: redaction logs redacted.prompt with unique/total/patterns", async () => {
    const n = events("redacted.prompt").length
    await triggerPrompt()
    const ev = events("redacted.prompt").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "info")
    assert.equal(typeof ev[0].unique, "number")
    assert.equal(typeof ev[0].total, "number")
    assert.ok(Array.isArray(ev[0].patterns) && ev[0].patterns.length >= 1)
    assert.equal(appLogs.at(-1)?.body?.service, "security-guard")
    assert.equal(appLogs.at(-1)?.body?.level, "info")
    assert.ok(String(appLogs.at(-1)?.body?.message).length > 0)
})

test("messages.transform: redacted.history carries unique/total/patterns", async () => {
    const v = novel()
    const n = events("redacted.history").length
    const out: any = { messages: [{ parts: [{ type: "text", text: v }] }] }
    await hooks["experimental.chat.messages.transform"]({}, out)
    const ev = events("redacted.history").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "info")
    assert.equal(typeof ev[0].unique, "number")
    assert.equal(typeof ev[0].total, "number")
    assert.ok(Array.isArray(ev[0].patterns) && ev[0].patterns.length >= 1)
})

test("messages.transform logs redacted.history once per fingerprint", async () => {
    const v = novel()
    const n = events("redacted.history").length
    const makeOut = () => ({ messages: [{ parts: [{ type: "text", text: v }] }] })
    await hooks["experimental.chat.messages.transform"]({}, makeOut())
    await hooks["experimental.chat.messages.transform"]({}, makeOut())
    assert.equal(events("redacted.history").length, n + 1, "a repeat fingerprint must not re-log")
})

test("system.transform: redaction logs redacted.system once per fingerprint", async () => {
    const v = novel()
    const n = events("redacted.system").length
    await hooks["experimental.chat.system.transform"]({}, { system: [v] })
    await hooks["experimental.chat.system.transform"]({}, { system: [v] })
    assert.equal(events("redacted.system").length, n + 1)
})

test("history dedup respects the LRU bound: the oldest fingerprint is evicted past 5000", async () => {
    const secretAt = (i: number): string => `api_key=Xy9kQ2mN7vR4tW8zB5c${i.toString(16).padStart(3, "0")}`
    const batch = Array.from({ length: 5001 }, (_, i) => secretAt(i)).join(" ")
    const n = events("redacted.history").length
    await hooks["experimental.chat.messages.transform"]({}, { messages: [{ parts: [{ type: "text", text: batch }] }] })
    const ev = events("redacted.history").slice(n)
    assert.equal(ev.length, 1, "the batch must log exactly once")
    assert.equal(ev[0].total, 5001, "every fingerprint in the batch must be novel")

    const after0 = events("redacted.history").length
    await hooks["experimental.chat.messages.transform"](
        {},
        { messages: [{ parts: [{ type: "text", text: secretAt(0) }] }] },
    )
    assert.equal(
        events("redacted.history").length,
        after0 + 1,
        "the oldest fingerprint must have been evicted, so it is novel again",
    )

    const after1 = events("redacted.history").length
    await hooks["experimental.chat.messages.transform"](
        {},
        { messages: [{ parts: [{ type: "text", text: secretAt(2) }] }] },
    )
    assert.equal(
        events("redacted.history").length,
        after1,
        "the fingerprint after the evicted one must still be remembered (the bound is strictly greater)",
    )
})

// ── chat hooks: remember() feeds later rehydration ────────────────────────
test("chat.message remembers secrets so their markers rehydrate later", async () => {
    const v = novel()
    const out: any = { parts: [{ type: "text", text: v }] }
    await hooks["chat.message"]({}, out)
    const marker = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(out.parts[0].text)?.[0]
    assert.ok(marker, `no marker produced: ${out.parts[0].text}`)
    const args = await rehydrateThrough(marker)
    assert.ok(!args.content.includes(MARKER), "the marker was not rehydrated")
})

test("messages.transform remembers secrets so their markers rehydrate later", async () => {
    const v = novel()
    const out: any = { messages: [{ parts: [{ type: "text", text: v }] }] }
    await hooks["experimental.chat.messages.transform"]({}, out)
    const marker = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(out.messages[0].parts[0].text)?.[0]
    assert.ok(marker, "no marker produced")
    const args = await rehydrateThrough(marker)
    assert.ok(!args.content.includes(MARKER), "the marker was not rehydrated")
})

test("system.transform remembers secrets so their markers rehydrate later", async () => {
    const v = novel()
    const out: any = { system: [v] }
    await hooks["experimental.chat.system.transform"]({}, out)
    const marker = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(out.system[0])?.[0]
    assert.ok(marker, "no marker produced")
    const args = await rehydrateThrough(marker)
    assert.ok(!args.content.includes(MARKER), "the marker was not rehydrated")
})

// ── alert delivery ────────────────────────────────────────────────────────
test("alert: a throwing app.log does not fail the hook and the log is still written", async () => {
    const orig = client.app.log
    client.app.log = async () => {
        throw new Error("client log down")
    }
    try {
        const n = events("redacted.prompt").length
        advance()
        await triggerPrompt()
        assert.equal(events("redacted.prompt").length, n + 1)
    } finally {
        client.app.log = orig
    }
})

test("alert: the toast uses the SDK v1 { body } shape", async () => {
    toasts.length = 0
    advance()
    await triggerPrompt()
    assert.equal(toasts.length, 1)
    const t: any = toasts[0]
    assert.equal(t.body.title, "security-guard")
    assert.equal(t.body.variant, "warning")
    assert.ok(String(t.body.message).length > 0)
})

test("alert: a rejecting v1 showToast falls back to the flat v2 shape", async () => {
    toasts.length = 0
    let calls = 0
    const orig = client.tui.showToast
    client.tui.showToast = async (i: any) => {
        calls++
        if (calls === 1) throw new Error("v1 rejected")
        toasts.push(i)
    }
    try {
        advance()
        await triggerPrompt()
    } finally {
        client.tui.showToast = orig
    }
    assert.equal(calls, 2)
    const t: any = toasts.at(-1)
    assert.equal(t.title, "security-guard")
    assert.equal(t.variant, "warning")
    assert.equal(t.body, undefined)
    assert.ok(String(t.message).length > 0)
})

test("alert: when both toast shapes reject the hook stays silent", async () => {
    toasts.length = 0
    let calls = 0
    const orig = client.tui.showToast
    client.tui.showToast = async () => {
        calls++
        throw new Error("nope")
    }
    try {
        advance()
        await assert.doesNotReject(() => triggerPrompt())
    } finally {
        client.tui.showToast = orig
    }
    assert.equal(calls, 2)
    assert.equal(toasts.length, 0)
})

test("alert: a second alert inside the cooldown produces no second toast", async () => {
    toasts.length = 0
    advance()
    await triggerPrompt()
    assert.equal(toasts.length, 1)
    await triggerPrompt()
    assert.equal(toasts.length, 1, "the second alert must respect the cooldown")
})

test("alert: a toast fires again once the cooldown has elapsed exactly", async () => {
    toasts.length = 0
    advance()
    await triggerPrompt()
    assert.equal(toasts.length, 1)
    now += TOAST_COOLDOWN_MS // exactly at the boundary: only `<` stays cool
    await triggerPrompt()
    assert.equal(toasts.length, 2)
})

// ── dispose: active session (keep last) ───────────────────────────────────
test("dispose: an active session writes the summary with blocks and counters", async () => {
    await assert.rejects(() => beforeHook("bash", { command: "cat .env" }))
    await triggerPrompt()
    const n = events("summary").length
    await hooks.dispose()
    const ev = events("summary").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "info")
    assert.ok(ev[0].blocks >= 1, "blocks must be counted")
    assert.equal(typeof ev[0].counters, "object")
    assert.ok(Object.keys(ev[0].counters).length >= 1, "counters must be non-empty")
    for (const value of Object.values(ev[0].counters)) assert.ok(Number(value) > 0, "counter must be positive")
})
