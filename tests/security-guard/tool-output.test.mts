// security-guard tool-output coverage (C3).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/tool-output.test.mts

import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-tool-log-")), "guard.log")

const { SecurityGuard } = await import("../../src/index.ts")
const { FAILED_PLACEHOLDER } = await import("../../src/redact.ts")

const hooks = await SecurityGuard({ client: {}, directory: process.cwd() })
const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const CRED = `api_key=${SECRET}`
const leaks = (v: any): boolean => JSON.stringify(v).includes(SECRET)

test("C3: attachment text is redacted", async () => {
    const output: any = { output: "ok", attachments: [{ type: "text", text: CRED }] }
    await hooks["tool.execute.after"]({ tool: "bash" }, output)
    assert.ok(!leaks(output.attachments), "attachment text leaked")
})

test("C3: a nested non-metadata field is redacted", async () => {
    const output: any = { output: "ok", data: { payload: CRED } }
    await hooks["tool.execute.after"]({ tool: "bash" }, output)
    assert.ok(!leaks(output.data), "nested field leaked")
})

test("C3: a metadata key is re-keyed and its value preserved", async () => {
    const output: any = { output: "ok", metadata: { [CRED]: "keep" } }
    await hooks["tool.execute.after"]({ tool: "bash" }, output)
    const keys = Object.keys(output.metadata)
    assert.ok(!keys.some((k) => k.includes(SECRET)), "secret key survived")
    assert.equal(output.metadata[keys[0]], "keep")
})

test("C3: primitive structural identifiers are preserved", async () => {
    const output: any = { output: "ok", id: CRED, callID: CRED }
    await hooks["tool.execute.after"]({ tool: "bash" }, output)
    assert.equal(output.id, CRED)
    assert.equal(output.callID, CRED)
})

test("C3: a secret nested under a skipped key is still redacted", async () => {
    const output: any = { output: "ok", meta: { type: { deep: CRED } } }
    await hooks["tool.execute.after"]({ tool: "bash" }, output)
    assert.ok(!leaks(output.meta), "secret under a skipped key leaked")
})

test("C3: a budget breach suppresses the whole output", async () => {
    let node: any = { leaf: CRED }
    for (let i = 0; i < 80; i++) node = { next: node }
    const output: any = { output: "ok", data: node, title: "t" }
    await hooks["tool.execute.after"]({ tool: "bash" }, output)
    assert.equal(output.output, FAILED_PLACEHOLDER)
    assert.equal(output.title, FAILED_PLACEHOLDER)
    assert.deepEqual(output.data, {})
})

test("C3: a redaction failure suppresses the whole output", async () => {
    const output: any = { output: "ok" }
    Object.defineProperty(output, "boom", {
        enumerable: true,
        configurable: true,
        get() {
            throw new Error("boom")
        },
    })
    await hooks["tool.execute.after"]({ tool: "bash" }, output)
    assert.equal(output.output, FAILED_PLACEHOLDER)
    assert.equal(output.boom, FAILED_PLACEHOLDER)
})
