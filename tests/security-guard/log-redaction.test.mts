// The log must never contain a secret value — only markers/rules/hashes.

import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
const LOG = join(mkdtempSync(join(tmpdir(), "sg-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

// Import AFTER setting the log path so config.ts picks up the temp file.
const { SecurityGuard } = await import("../../src/index.ts")
// A real directory: `/tmp` does not exist on Windows and would trip the
// canonical fail-closed destination check.
const ROOT = mkdtempSync(join(tmpdir(), "sg-log-redact-root-"))
const hooks = await SecurityGuard({ client: {}, directory: ROOT })

test("the log never contains a secret value", async () => {
    const output: any = { output: `api_key=${SECRET}`, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, output)

    const marker = /<[^>]+:[^:>]+:[0-9a-f]{16}>/.exec(String(output.output))
    assert.ok(marker, "no marker produced")

    // exercise the rehydration path too (logs hashes, never the value)
    await hooks["tool.execute.before"](
        { tool: "write" },
        { args: { filePath: join(ROOT, "sg-log-out.txt"), content: `api_key=${marker[0]}` } },
    )

    const log = readFileSync(LOG, "utf8")
    assert.ok(/redacted\.tool|rehydrated/.test(log), "expected log events")
    assert.ok(!log.includes(SECRET), "secret value leaked into the log")
})

test("the log never contains a decoded secret value", async () => {
    const decoded = "AKIA" + "A1B2C3D4E5F6G7H8"
    const enc = Buffer.from(decoded).toString("base64")
    const output: any = { output: `blob=${enc}`, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, output)
    const log = readFileSync(LOG, "utf8")
    assert.ok(!log.includes(decoded), "decoded value leaked into the log")
})
