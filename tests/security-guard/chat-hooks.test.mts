// security-guard chat hooks suite: system prompt + message parts/info redaction.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/chat-hooks.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// Temp log set BEFORE importing config (read at module load) so this suite
// never pollutes the production log.
const LOG = join(mkdtempSync(join(tmpdir(), "sg-chat-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
// A real project root: on Windows a non-existent root (/tmp) fails closed and
// would classify every write destination as sensitive.
const PROJECT = mkdtempSync(join(tmpdir(), "sg-chat-project-"))

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER, LOG_FILE } = await import("../../src/config.ts")
const { scan } = await import("../../src/rules.ts")
const { redactStrings, redactDeep, FAILED_PLACEHOLDER } = await import("../../src/redact.ts")

const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const CRED = `api_key=${SECRET}`

// Reviewed deterministic fixtures (make-test-suite-reproducible): the
// structural-identifier precondition and the log-dedup value must not depend
// on unseeded randomness. Both are synthetic and non-production. DEDUP_CRED
// must stay unique within this file: an earlier redaction of the same value
// would already be in the seen-history set and the +1 log assertion below
// would fail loudly, not silently.
const HIGH_ENTROPY_ID = "StructuralIdA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" // 52 chars → entropy-blob
const DEDUP_CRED = "api_key=DedupFixtureA1b2C3d4E5" // → bare-credential

const hooks = await SecurityGuard({ client: {}, directory: PROJECT })

test("chat.message redacts parts and message.system", async () => {
    const output: any = {
        message: {
            id: "m1",
            sessionID: "s",
            role: "user",
            agent: "build",
            time: { created: 1 },
            model: { providerID: "p", modelID: "m" },
            system: CRED,
        },
        parts: [{ type: "text", text: CRED }],
    }
    await hooks["chat.message"]({ sessionID: "s" }, output)
    assert.ok(!output.parts[0].text.includes(SECRET))
    assert.ok(output.parts[0].text.includes(MARKER))
    assert.ok(!output.message.system.includes(SECRET))
    assert.ok(output.message.system.includes(MARKER))
})

test("messages.transform redacts parts and info", async () => {
    const output: any = {
        messages: [
            {
                info: {
                    id: "m1",
                    sessionID: "s",
                    role: "user",
                    agent: "build",
                    parentID: "p1",
                    modelID: "mdl",
                    providerID: "prv",
                    time: { created: 1 },
                    tokens: { input: 1 },
                    system: CRED,
                    summary: { title: CRED, body: CRED, diffs: [] },
                    error: { name: "UnknownError", data: { message: CRED } },
                    path: { cwd: CRED, root: "/tmp" },
                },
                parts: [{ type: "text", text: CRED }],
            },
        ],
    }
    await hooks["experimental.chat.messages.transform"]({}, output)
    const info = output.messages[0].info
    assert.ok(!info.system.includes(SECRET))
    assert.ok(!info.summary.title.includes(SECRET))
    assert.ok(!info.summary.body.includes(SECRET))
    assert.ok(!info.error.data.message.includes(SECRET))
    assert.ok(!info.path.cwd.includes(SECRET))
    assert.ok(!output.messages[0].parts[0].text.includes(SECRET))
})

test("structural identifiers are preserved (high entropy)", async () => {
    const pre = scan(HIGH_ENTROPY_ID)
    assert.equal(
        pre.hits.find((h) => h.rule === "entropy-blob")?.value,
        HIGH_ENTROPY_ID,
        "precondition: the value is redactable by entropy-blob",
    )
    const output: any = {
        messages: [
            {
                info: {
                    id: HIGH_ENTROPY_ID,
                    sessionID: HIGH_ENTROPY_ID,
                    parentID: HIGH_ENTROPY_ID,
                    modelID: HIGH_ENTROPY_ID,
                    providerID: HIGH_ENTROPY_ID,
                    agent: "build",
                    role: "assistant",
                    mode: "build",
                    time: { created: 1 },
                    tokens: { input: 1 },
                    cost: 0,
                },
                parts: [],
            },
        ],
    }
    await hooks["experimental.chat.messages.transform"]({}, output)
    const info = output.messages[0].info
    for (const k of ["id", "sessionID", "parentID", "modelID", "providerID"]) {
        assert.equal(info[k], HIGH_ENTROPY_ID, `${k} must be preserved`)
    }
})

test("system.transform redacts, remembers and rehydrates on write", async () => {
    const output: any = { system: [CRED, "keep me"] }
    await hooks["experimental.chat.system.transform"]({}, output)
    assert.ok(!output.system[0].includes(SECRET))
    assert.ok(output.system[0].includes(MARKER))
    assert.equal(output.system[1], "keep me")

    const marker = output.system[0]
    const call: any = { args: { filePath: join(PROJECT, "sg-chat-hook-out.txt"), content: marker } }
    await hooks["tool.execute.before"]({ tool: "write" }, call)
    assert.equal(call.args.content, CRED)
})

test("idempotency: markers are not re-redacted", async () => {
    const first: any = { system: [CRED] }
    await hooks["experimental.chat.system.transform"]({}, first)
    const marker = first.system[0]
    const second: any = { system: [marker] }
    await hooks["experimental.chat.system.transform"]({}, second)
    assert.equal(second.system[0], marker)
})

test("per-string fail-closed: a throwing scanner yields a placeholder and logs an ERROR", () => {
    const scanFn = (text: string) => {
        if (text === "boom") throw new Error("scanner exploded")
        return { text, hits: [] }
    }
    const count = () => (readFileSync(LOG_FILE, "utf8").match(/"event":"redaction\.failed"/g) ?? []).length
    const before = count()
    const hits: any[] = []
    assert.deepEqual(redactStrings(["ok", "boom", "fine"], hits, { scanFn, at: "test" }), [
        "ok",
        FAILED_PLACEHOLDER,
        "fine",
    ])
    assert.deepEqual(redactDeep({ a: "ok", b: "boom" }, hits, new WeakSet(), { scanFn, at: "test" }), {
        a: "ok",
        b: FAILED_PLACEHOLDER,
    })
    assert.equal(count() - before, 2, "each failed string logs one redaction.failed ERROR")
    const failures = readFileSync(LOG_FILE, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>)
        .filter((event) => event.event === "redaction.failed")
    assert.ok(failures.some((event) => event.at === "test" && event.index === 1))
    assert.ok(failures.some((event) => event.at === "test" && !("index" in event)))
})

test("system.transform dedups the log by fingerprint", async () => {
    assert.ok(
        scan(DEDUP_CRED).hits.some((h) => h.rule === "bare-credential"),
        "precondition: the dedup fixture is redactable",
    )
    const count = () => (readFileSync(LOG_FILE, "utf8").match(/"event":"redacted\.system"/g) ?? []).length
    const before = count()
    await hooks["experimental.chat.system.transform"]({}, { system: [DEDUP_CRED] })
    await hooks["experimental.chat.system.transform"]({}, { system: [DEDUP_CRED] })
    assert.equal(count() - before, 1)
})

test("system.transform preserves the array identity (C1)", async () => {
    const arr = [CRED, "keep me"]
    const output: any = { system: arr }
    await hooks["experimental.chat.system.transform"]({}, output)
    assert.equal(output.system, arr, "array reference must be preserved")
    assert.ok(!output.system[0].includes(SECRET))
    assert.equal(output.system[1], "keep me")
})

test("system.transform handles an absent array (C1)", async () => {
    const output: any = {}
    await hooks["experimental.chat.system.transform"]({}, output)
    assert.ok(Array.isArray(output.system), "a redacted array must be assigned")
})
