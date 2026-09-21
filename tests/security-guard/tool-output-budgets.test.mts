// Tool-output traversal-budget boundaries and structural guards: each budget
// accepts its exact boundary and rejects one past it, the WeakSet cuts cycles
// instead of recursing to the depth error, and arrays are rewritten in place
// without growing. The scanner is injected so fixtures stay deterministic and
// cheap (the 4 MiB case never runs the regex corpus); one case runs the default
// scanner to catch decoupling from the production scan path.
//
// The 64 / 20 000 / 4 * 1024 * 1024 constants are a pinned contract (design D3):
// a deliberate budget change must update these tests in the same change.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/tool-output-budgets.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { redactToolValue } from "../../src/tool-output.ts"
import type { ScanFn } from "../../src/redact.ts"
import type { Hit } from "../../src/rules.ts"

const CANARY = "sg-canary-9f2c7a1e"
const STUB_REDACTED = "[stub-redacted]"

const stubScan: ScanFn = (text) =>
    text.includes(CANARY)
        ? { text: STUB_REDACTED, hits: [{ rule: "stub", fp: "stub-fp", value: CANARY }] }
        : { text, hits: [] }

const MAX_DEPTH = 64
const MAX_NODES = 20000
const MAX_STRING = 4 * 1024 * 1024

test("budget: depth is accepted at the boundary and rejected one past it", () => {
    assert.equal(redactToolValue("leaf", [], { nodes: 0 }, { scanFn: stubScan }, MAX_DEPTH), "leaf")
    assert.throws(() => redactToolValue("leaf", [], { nodes: 0 }, { scanFn: stubScan }, MAX_DEPTH + 1), /depth budget/)
})

test("budget: node visits are accepted at the limit and rejected one past it", () => {
    const state = { nodes: 0 }
    const hits: Hit[] = []
    for (let i = 0; i < MAX_NODES; i++) redactToolValue(i, hits, state, { scanFn: stubScan })
    assert.equal(state.nodes, MAX_NODES)
    assert.throws(() => redactToolValue(0, hits, state, { scanFn: stubScan }), /node budget/)
})

test("budget: a string of exactly the limit is accepted", () => {
    const exact = "a".repeat(MAX_STRING)
    assert.equal(redactToolValue(exact, [], { nodes: 0 }, { scanFn: stubScan }), exact)
})

test("budget: a string one char past the limit is rejected", () => {
    const over = "a".repeat(MAX_STRING + 1)
    assert.throws(() => redactToolValue(over, [], { nodes: 0 }, { scanFn: stubScan }), /string budget/)
})

test("guard: null and undefined inputs pass through untouched", () => {
    assert.equal(redactToolValue(null, [], { nodes: 0 }, { scanFn: stubScan }), null)
    assert.equal(redactToolValue(undefined, [], { nodes: 0 }, { scanFn: stubScan }), undefined)
})

test("scanner: the default scanner still redacts a non-skipped field", () => {
    const token = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("")
    const out = redactToolValue({ data: token }, [], { nodes: 0 })
    assert.ok(!JSON.stringify(out).includes("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"), "raw token leaked")
})

test("budget: a deep array chain beyond the depth limit is rejected", () => {
    let nested: unknown = [CANARY]
    for (let i = 0; i < MAX_DEPTH + 1; i++) nested = [nested]
    assert.throws(() => redactToolValue(nested, [], { nodes: 0 }, { scanFn: stubScan }), /depth budget/)
})

test("cycle: an object cycle is cut by the seen guard", () => {
    const node: Record<string, unknown> = { safe: CANARY }
    node.self = node
    const hits: Hit[] = []
    const out = redactToolValue(node, hits, { nodes: 0 }, { scanFn: stubScan }) as Record<string, unknown>
    assert.equal(out.self, out)
    assert.equal(out.safe, STUB_REDACTED)
})

test("cycle: an array cycle is cut by the seen guard", () => {
    const arr: unknown[] = [CANARY]
    arr.push(arr)
    const hits: Hit[] = []
    const out = redactToolValue(arr, hits, { nodes: 0 }, { scanFn: stubScan }) as unknown[]
    assert.equal(out[1], out)
    assert.equal(out[0], STUB_REDACTED)
    assert.equal(out.length, 2)
})

test("array: elements are redacted in place and the length is unchanged", () => {
    const arr: unknown[] = [CANARY, { nested: CANARY }]
    const hits: Hit[] = []
    const out = redactToolValue(arr, hits, { nodes: 0 }, { scanFn: stubScan }) as unknown[]
    assert.equal(out.length, 2)
    assert.equal(out[0], STUB_REDACTED)
    assert.equal((out[1] as Record<string, unknown>).nested, STUB_REDACTED)
    assert.equal(hits.length, 2)
})
