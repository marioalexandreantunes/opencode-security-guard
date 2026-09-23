// security-guard fail-closed marker inspection suite: write arguments that
// cannot be serialized for marker inspection are explicitly blocked with a
// stable coded diagnostic — never an uncaught exception and never a false
// "no markers" pass. Synthetic values only.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/marker-inspection.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-inspect-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER } = await import("../../src/config.ts")

const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const CRED = `api_key=${SECRET}`
const project = mkdtempSync(join(tmpdir(), "sg-inspect-project-"))
const inside = join(project, "inside.txt")

const hooks: any = await SecurityGuard({ client: {}, directory: project, worktree: project })

const readLog = (): string => {
    try {
        return readFileSync(LOG, "utf8")
    } catch {
        return ""
    }
}
const inspectionBlocks = (): any[] =>
    readLog()
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l))
        .filter((e) => e.event === "blocked.marker-inspection")

async function seed(): Promise<string> {
    const output: any = { output: CRED, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "seed", callID: "seed" }, output)
    const m = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(String(output.output))
    assert.ok(m, `no marker minted: ${output.output}`)
    return m[0]
}
const marker = await seed()
const withMarker = (extra: Record<string, unknown> = {}): any => ({
    filePath: inside,
    content: `key=${marker}`,
    ...extra,
})

test("inspection: cyclic arguments are explicitly blocked, not thrown", async () => {
    const args: any = withMarker()
    args.self = args
    const n = inspectionBlocks().length
    await assert.rejects(
        () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args }),
        /could not be inspected/,
        "a cycle must reject with the stable inspection message",
    )
    const ev = inspectionBlocks().slice(n)
    assert.equal(ev.length, 1, "exactly one coded inspection record")
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].tool, "write")
    assert.equal(ev[0].error, "marker-inspection-failed")
    assert.ok(!readLog().includes(SECRET), "the raw secret leaked into the log")
    assert.ok(!readLog().includes("circular"), "the engine message leaked into the log")
})

test("inspection: BigInt arguments are explicitly blocked", async () => {
    const args: any = withMarker({ nonce: 12345678901234567890n })
    const n = inspectionBlocks().length
    await assert.rejects(
        () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args }),
        /could not be inspected/,
    )
    const ev = inspectionBlocks().slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].error, "marker-inspection-failed")
    assert.ok(!readLog().includes("BigInt"), "the engine message leaked into the log")
})

test("inspection: throwing accessors are explicitly blocked", async () => {
    const args: any = { filePath: inside }
    Object.defineProperty(args, "content", {
        enumerable: true,
        get() {
            throw new Error("getter-boom-marker")
        },
    })
    const n = inspectionBlocks().length
    await assert.rejects(
        () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args }),
        /could not be inspected/,
    )
    const ev = inspectionBlocks().slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].error, "marker-inspection-failed")
    assert.ok(!readLog().includes("getter-boom-marker"), "the getter message leaked into the log")
})

test("inspection: throwing target accessors are blocked before path extraction", async () => {
    const args: any = {}
    Object.defineProperty(args, "filePath", {
        enumerable: false,
        get() {
            throw new Error("file-path-getter-boom")
        },
    })
    const n = inspectionBlocks().length
    await assert.rejects(
        () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args }),
        /could not be inspected/,
    )
    const ev = inspectionBlocks().slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].error, "marker-inspection-failed")
    assert.ok(!readLog().includes("file-path-getter-boom"), "the getter message leaked into the log")
})

test("inspection: the disabled-rehydration path blocks uninspectable args too", async () => {
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const args: any = withMarker()
        args.self = args
        const n = inspectionBlocks().length
        await assert.rejects(
            () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args }),
            /could not be inspected/,
        )
        assert.equal(inspectionBlocks().length, n + 1)
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("inspection: inspectable writes keep their normal marker behaviour", async () => {
    const args: any = withMarker()
    await hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args })
    assert.ok(String(args.content).includes(SECRET), "a known marker must still rehydrate")
})
