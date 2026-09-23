// security-guard characterization: MODE=block blocks sensitive reads by name.
// MODE is read at config load, so this needs its own process/file.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/read-block.test.mts

import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

process.env.SECURITY_GUARD_MODE = "block"

const { SecurityGuard } = await import("../../src/index.ts")
// A real directory: `/tmp` does not exist on Windows, so the canonical
// (fail-closed) check would classify an ordinary filename as sensitive.
const ROOT = mkdtempSync(join(tmpdir(), "sg-read-block-"))
const hooks = await SecurityGuard({ client: {}, directory: ROOT })

const read = (filePath: string) =>
    hooks["tool.execute.before"]({ tool: "read", sessionID: "s", callID: "c" }, { args: { filePath } })

test("characterization: MODE=block blocks a sensitive read by name", async () => {
    await assert.rejects(() => read(".env"), /read blocked/)
})

test("characterization: MODE=block still allows a non-sensitive read", async () => {
    await assert.doesNotReject(() => read("notes.txt"))
})

test("characterization: MODE=block blocks a read inside .security-guard/", async () => {
    await assert.rejects(() => read(".security-guard/blacklist"), /read blocked/)
    await assert.rejects(() => read("/home/dev/proj/.security-guard/security-guard.log"), /read blocked/)
})
