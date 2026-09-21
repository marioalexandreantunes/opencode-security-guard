// security-guard characterization: the dispose `summary` event reports blocks
// and per-rule counters. Dedicated file because dispose ends the factory.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/summary-log.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-summary-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const hooks = await SecurityGuard({ client: {}, directory: "/tmp" })

test("characterization: summary reports blocks and counters", async () => {
    await assert.rejects(() =>
        hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: "cat .env" } }),
    )
    const output: any = { output: "api_key=" + "Xy9kQ2mN7vR4tW8zB5c", metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, output)
    await hooks.dispose()

    const events = readFileSync(LOG, "utf8")
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l))
    const summary = events.find((e) => e.event === "summary")
    assert.ok(summary, "no summary event")
    assert.ok(summary.blocks >= 1, "blocks not counted")
    assert.equal(typeof summary.counters, "object")
    assert.ok(Object.keys(summary.counters).length >= 1, "counters empty")
})
