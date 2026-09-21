// neutraliseOutput fail-closed path: strings/arrays/objects collapse by type,
// primitives survive, skipped keys stay untouched, throwing getters and
// getter-only accessors become enumerable data properties, and the output key
// is always set. No scanner runs here — the function only inspects types.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/tool-output-neutralise.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { TOOL_SKIP, neutraliseOutput } from "../../src/tool-output.ts"
import { FAILED_PLACEHOLDER } from "../../src/redact.ts"

test("neutralise: values collapse by type and primitives survive", () => {
    const output: Record<string, unknown> = {
        output: "raw",
        title: "text",
        items: [1, "two"],
        meta: { nested: "value" },
        count: 3,
        flag: true,
        none: null,
    }
    neutraliseOutput(output)
    assert.equal(output.output, FAILED_PLACEHOLDER)
    assert.equal(output.title, FAILED_PLACEHOLDER)
    assert.deepEqual(output.items, [])
    assert.deepEqual(output.meta, {})
    assert.equal(output.count, 3)
    assert.equal(output.flag, true)
    assert.equal(output.none, null)
})

test("neutralise: skipped keys stay untouched whatever the value type", () => {
    const key = [...TOOL_SKIP][0]
    const output: Record<string, unknown> = { output: "raw", [key]: { nested: "value" } }
    neutraliseOutput(output)
    assert.deepEqual(output[key], { nested: "value" })
    assert.equal(output.output, FAILED_PLACEHOLDER)
})

test("neutralise: a throwing getter becomes the placeholder", () => {
    const output: Record<string, unknown> = { output: "raw" }
    Object.defineProperty(output, "boom", {
        enumerable: true,
        configurable: true,
        get() {
            throw new Error("boom")
        },
    })
    neutraliseOutput(output)
    assert.equal(output.boom, FAILED_PLACEHOLDER)
})

test("neutralise: a getter-only property becomes an enumerable data property", () => {
    const output: Record<string, unknown> = { output: "raw" }
    Object.defineProperty(output, "locked", {
        enumerable: true,
        configurable: true,
        get() {
            return "text"
        },
    })
    neutraliseOutput(output)
    const descriptor = Object.getOwnPropertyDescriptor(output, "locked")
    assert.ok(descriptor, "property descriptor missing")
    assert.equal(descriptor.value, FAILED_PLACEHOLDER)
    assert.equal(descriptor.enumerable, true)
    assert.equal(descriptor.writable, true)
    assert.equal(descriptor.configurable, true)
})

test("neutralise: a throwing getter under a skipped key is not read", () => {
    const key = [...TOOL_SKIP][1]
    const output: Record<string, unknown> = {}
    Object.defineProperty(output, key, {
        enumerable: true,
        configurable: true,
        get() {
            throw new Error("skipped key must not be read")
        },
    })
    neutraliseOutput(output)
    assert.throws(() => output[key], /skipped key must not be read/)
})

test("neutralise: output is set even when absent or an object", () => {
    const output: Record<string, unknown> = { output: { deep: "value" } }
    neutraliseOutput(output)
    assert.equal(output.output, FAILED_PLACEHOLDER)
})
