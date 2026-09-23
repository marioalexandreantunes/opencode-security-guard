// security-guard redact-mode pin for linked sensitive reads: reading through
// an innocent-named link stays allowed but the output is redacted before
// inference. Synthetic temp fixtures only. The file link is created after a
// one-time capability probe so an unprivileged Windows host skips only the two
// link scenarios instead of failing the file.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/sensitive-path-canonical-redact.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { fileLinkSkipReason, linkFile } from "./platform-fixtures.mts"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-sens-redact-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER } = await import("../../src/config.ts")

const ROOT = mkdtempSync(join(tmpdir(), "sg-sens-redact-root-"))
const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
writeFileSync(join(ROOT, ".env"), `api_key=${SECRET}\n`)
const SKIP_FILE_LINK = fileLinkSkipReason()

const makeFileLink = (name: string): string => {
    const link = join(ROOT, name)
    linkFile(join(ROOT, ".env"), link)
    return link
}

const hooks: any = await SecurityGuard({ client: {}, directory: ROOT, worktree: ROOT })

test("sensitive-canonical-redact: reading through the link is allowed", { skip: SKIP_FILE_LINK }, async () => {
    const link = makeFileLink("notes-link.txt")
    await assert.doesNotReject(() =>
        hooks["tool.execute.before"]({ tool: "read", sessionID: "s", callID: "c" }, { args: { filePath: link } }),
    )
})

test("sensitive-canonical-redact: read output is redacted", async () => {
    const output: any = { output: `api_key=${SECRET}`, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "read", sessionID: "s", callID: "c" }, output)
    assert.ok(!String(output.output).includes(SECRET), "the raw secret leaked to the model")
    assert.ok(String(output.output).includes(MARKER), "no marker minted for the secret")
})
