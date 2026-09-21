// Tool-output TOOL_SKIP matrix: every structural key literal is pinned for the
// deep redaction (primitive values preserved, objects and arrays still redacted)
// and for the fail-closed neutralisation (skipped keys left untouched). A
// deterministic injected scanner isolates the tool-output logic from the rules
// corpus; one case runs the default scanner to catch decoupling from the real
// pipeline.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/tool-output-skip.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { TOOL_SKIP, redactToolValue, neutraliseOutput } from "../../src/tool-output.ts"
import { FAILED_PLACEHOLDER, type ScanFn } from "../../src/redact.ts"
import { MARKER } from "../../src/config.ts"
import type { Hit } from "../../src/rules.ts"

const CANARY = "sg-canary-9f2c7a1e"
const STUB_REDACTED = "[stub-redacted]"

const stubScan: ScanFn = (text) =>
    text.includes(CANARY)
        ? { text: STUB_REDACTED, hits: [{ rule: "stub", fp: "stub-fp", value: CANARY }] }
        : { text, hits: [] }

test("TOOL_SKIP: the full member set is pinned", () => {
    assert.deepEqual([...TOOL_SKIP].sort(), [
        "callID",
        "cost",
        "id",
        "messageID",
        "role",
        "sessionID",
        "time",
        "tokens",
        "type",
    ])
})

for (const key of TOOL_SKIP) {
    test(`TOOL_SKIP: a primitive value under "${key}" is preserved by redactToolValue`, () => {
        const record: Record<string, unknown> = { [key]: CANARY }
        const hits: Hit[] = []
        const out = redactToolValue(record, hits, { nodes: 0 }, { scanFn: stubScan }) as Record<string, unknown>
        assert.equal(out[key], CANARY)
        assert.equal(hits.length, 0)
    })

    test(`TOOL_SKIP: null under "${key}" is preserved by redactToolValue`, () => {
        const record: Record<string, unknown> = { [key]: null }
        const hits: Hit[] = []
        const out = redactToolValue(record, hits, { nodes: 0 }, { scanFn: stubScan }) as Record<string, unknown>
        assert.equal(out[key], null)
        assert.equal(hits.length, 0)
    })

    test(`TOOL_SKIP: an object value under "${key}" is still redacted`, () => {
        const record: Record<string, unknown> = { [key]: { deep: CANARY } }
        const hits: Hit[] = []
        const out = redactToolValue(record, hits, { nodes: 0 }, { scanFn: stubScan }) as Record<string, unknown>
        assert.equal((out[key] as Record<string, unknown>).deep, STUB_REDACTED)
        assert.equal(hits.length, 1)
    })

    test(`TOOL_SKIP: an array value under "${key}" is still redacted`, () => {
        const record: Record<string, unknown> = { [key]: [CANARY, { deep: CANARY }] }
        const hits: Hit[] = []
        const out = redactToolValue(record, hits, { nodes: 0 }, { scanFn: stubScan }) as Record<string, unknown>
        const arr = out[key] as unknown[]
        assert.equal(arr[0], STUB_REDACTED)
        assert.equal((arr[1] as Record<string, unknown>).deep, STUB_REDACTED)
        assert.equal(hits.length, 2)
    })

    test(`TOOL_SKIP: neutraliseOutput leaves "${key}" untouched`, () => {
        const output: Record<string, unknown> = { output: "raw", [key]: CANARY }
        neutraliseOutput(output)
        assert.equal(output[key], CANARY)
        assert.equal(output.output, FAILED_PLACEHOLDER)
    })
}

test("TOOL_SKIP: a secret-bearing key is re-keyed and its value preserved", () => {
    const record: Record<string, unknown> = { [`meta-${CANARY}`]: "keep" }
    const hits: Hit[] = []
    const out = redactToolValue(record, hits, { nodes: 0 }, { scanFn: stubScan }) as Record<string, unknown>
    const keys = Object.keys(out)
    assert.equal(keys.length, 1)
    assert.ok(!keys[0].includes(CANARY), "secret-bearing key survived")
    assert.equal(out[keys[0]], "keep")
    assert.equal(hits.length, 1)
})

test("TOOL_SKIP: interleaved skipped keys keep their position", () => {
    const record: Record<string, unknown> = { id: null, alpha: "one", time: "when", beta: "two" }
    const out = redactToolValue(record, [], { nodes: 0 }, { scanFn: stubScan }) as Record<string, unknown>
    assert.deepEqual(Object.keys(out), ["id", "alpha", "time", "beta"])
})

test("TOOL_SKIP: the default scanner still redacts a non-skipped field", () => {
    const credential = `${"api"}_key="${"9f8e7d6c5b4a3210"}"`
    const out = redactToolValue({ data: credential }, [], { nodes: 0 })
    const text = JSON.stringify(out)
    assert.ok(!text.includes("9f8e7d6c5b4a3210"), "raw credential leaked")
    assert.ok(text.includes(MARKER), "expected a marker replacement")
})
