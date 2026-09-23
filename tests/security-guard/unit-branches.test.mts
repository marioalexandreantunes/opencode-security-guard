// Unit tests for internal branches not exercised through the plugin hooks.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/unit-branches.test.mts

import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, parse, resolve } from "node:path"
import { test } from "node:test"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-unit-")), "guard.log")

const { redactStrings, redactDeep, redactSkipping, FAILED_PLACEHOLDER } = await import("../../src/redact.ts")
const { redactToolValue, neutraliseOutput } = await import("../../src/tool-output.ts")
const { createVault } = await import("../../src/vault.ts")
const { resolveProjectRoot, isInsideWorktree, writeTargets } = await import("../../src/write-policy.ts")
const { mixedBlob } = await import("../../src/rules.ts")

test("redactStrings: default scanner leaves clean strings untouched", () => {
    const hits: any[] = []
    assert.deepEqual(redactStrings(["plain", "also plain"], hits), ["plain", "also plain"])
    assert.equal(hits.length, 0)
})

test("redactDeep: primitives and arrays pass through with the default scanner", () => {
    const hits: any[] = []
    assert.equal(redactDeep(null, hits), null)
    assert.equal(redactDeep(42, hits), 42)
    assert.equal(redactDeep(true, hits), true)
    assert.deepEqual(redactDeep([1, "plain"], hits), [1, "plain"])
})

test("redactDeep: nested secrets are redacted and cycles are preserved", () => {
    const hits: any[] = []
    const secret = "api_key=" + "Xy9kQ2mN7vR4tW8zB5c"
    const value: { nested: string[]; self?: unknown } = { nested: [secret] }
    value.self = value

    const result = redactDeep(value, hits) as typeof value
    assert.notEqual(result.nested[0], secret, "nested secret must be replaced")
    assert.equal(result.self, result, "the cycle must not be traversed twice")
    assert.equal(hits.length, 1)
})

test("redactSkipping: a non-object input is a no-op", () => {
    const hits: any[] = []
    assert.doesNotThrow(() => redactSkipping(null, hits, new Set(["x"])))
    assert.doesNotThrow(() => redactSkipping(7, hits, new Set(["x"])))
})

test("redactToolValue: arrays and primitives", () => {
    const hits: any[] = []
    assert.equal(redactToolValue(7, hits, { nodes: 0 }), 7)
    assert.deepEqual(redactToolValue([1, 2], hits, { nodes: 0 }), [1, 2])
})

test("redactToolValue: an injectable scanner is used for values and keys", () => {
    const calls: string[] = []
    const scanFn = (text: string) => {
        calls.push(text)
        return { text: text.replace(/x/g, "y"), hits: [] }
    }
    const value = { xkey: "xvalue" }
    const out = redactToolValue(value, [], { nodes: 0 }, { scanFn }) as any
    assert.deepEqual(out, { ykey: "yvalue" })
    assert.ok(calls.includes("xkey"), "the key was not scanned")
    assert.ok(calls.includes("xvalue"), "the value was not scanned")
})

test("redactToolValue: depth, node and string budgets fail closed", () => {
    const hits: any[] = []
    assert.throws(() => redactToolValue("x", hits, { nodes: 0 }, {}, 65), /depth budget/)
    assert.throws(() => redactToolValue("x", hits, { nodes: 20001 }), /node budget/)
    assert.throws(() => redactToolValue("x".repeat(4 * 1024 * 1024 + 1), hits, { nodes: 0 }), /string budget/)
})

test("neutraliseOutput: drops string, array and object values, keeps structural ids", () => {
    const output: any = { output: "keep", arr: [1], obj: { a: 1 }, id: "struct" }
    neutraliseOutput(output)
    assert.equal(output.output, FAILED_PLACEHOLDER)
    assert.deepEqual(output.arr, [])
    assert.deepEqual(output.obj, {})
    assert.equal(output.id, "struct")
})

test("vault: an invalid SECURITY_GUARD_VAULT_MAX falls back to the default", () => {
    const previous = process.env.SECURITY_GUARD_VAULT_MAX
    process.env.SECURITY_GUARD_VAULT_MAX = "not-a-number"
    try {
        const vault = createVault()
        vault.store("a", "1")
        assert.equal(vault.lookup("a"), "1")
    } finally {
        if (previous === undefined) delete process.env.SECURITY_GUARD_VAULT_MAX
        else process.env.SECURITY_GUARD_VAULT_MAX = previous
    }
})

test("write-policy: resolveProjectRoot falls back to cwd", () => {
    assert.equal(resolveProjectRoot(undefined, undefined), process.cwd())
    assert.equal(resolveProjectRoot("   ", ""), process.cwd())
    assert.equal(resolveProjectRoot("proj", undefined), resolve("proj"))
})

test("write-policy: resolveProjectRoot ignores filesystem-root placeholder", () => {
    const filesystemRoot = parse(process.cwd()).root
    const project = resolve("non-git-project")
    assert.equal(resolveProjectRoot(filesystemRoot, project), project)
    assert.equal(resolveProjectRoot("/", project), project)
})

test("write-policy: resolveProjectRoot keeps normal worktree precedence", () => {
    const worktree = resolve("worktree")
    const directory = resolve("directory")
    assert.equal(resolveProjectRoot(worktree, directory), worktree)
    assert.equal(resolveProjectRoot(parse(process.cwd()).root, parse(process.cwd()).root), parse(process.cwd()).root)
})

test("write-policy: isInsideWorktree and writeTargets edge cases", () => {
    assert.equal(isInsideWorktree("/a", ""), true)
    assert.equal(isInsideWorktree("/a", "../b"), false)
    assert.deepEqual(writeTargets(null), [])
    assert.deepEqual(writeTargets({ filePath: "/x", path: "" }), ["/x"])
    assert.deepEqual(
        writeTargets({
            patchText:
                "prefix *** Add File: src/ignored.ts\n" +
                "*** Add File:src/no-space.ts\n" +
                "*** Update File:\tsrc/tab.ts\n" +
                "*** Move to:   src/move.ts\n" +
                "*** Delete File: src/delete.ts\n" +
                "*** Add File:src/trailing.ts   \n",
        }),
        ["src/no-space.ts", "src/tab.ts", "src/move.ts", "src/delete.ts", "src/trailing.ts"],
    )
    if (process.platform === "win32") {
        assert.equal(isInsideWorktree("C:\\work", "D:\\outside"), false)
    }
})

test("rules: mixedBlob requires mixed case, digits and real entropy", () => {
    // values calibrated against the live entropy() (change evidence)
    assert.equal(mixedBlob("aB3xY7kM2pQ5vW1zC4fH6jL9dGhJqRs"), true)
    assert.equal(mixedBlob("Ab1".repeat(11)), false, "repetitive blob: entropy below the mixed threshold")
    assert.equal(mixedBlob("deadbeefcafe1234567890abcdef1234"), false, "lowercase hex lacks mixed case")
})
