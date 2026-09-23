// security-guard canonical sensitive-path suite: a link with an innocent name
// that resolves to a sensitive file is treated as sensitive (block mode).
// Synthetic temp fixtures only. Link fixtures are created after a one-time
// capability probe, so an unprivileged Windows host skips only the file-link
// scenarios instead of failing the whole file at load.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/sensitive-path-canonical.test.mts

import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { fileLinkSkipReason, linkDir, linkFile } from "./platform-fixtures.mts"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-sens-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG
process.env.SECURITY_GUARD_MODE = "block"

const { SecurityGuard } = await import("../../src/index.ts")
const { isSensitivePath, isSensitivePathFor } = await import("../../src/paths.ts")
const { getProjectContext } = await import("../../src/config.ts")

const ROOT = mkdtempSync(join(tmpdir(), "sg-sens-root-"))
const SECRET = "Xy9kQ2mN7vR4tW8zB5c"
writeFileSync(join(ROOT, ".env"), `api_key=${SECRET}\n`)
writeFileSync(join(ROOT, "ok.txt"), "plain\n")
mkdirSync(join(ROOT, ".security-guard"), { recursive: true })

const SKIP_FILE_LINK = fileLinkSkipReason()

const makeFileLink = (target: string, name: string): string => {
    const link = join(ROOT, name)
    linkFile(target, link)
    return link
}

const scope = { logFile: LOG, root: ROOT }
const hooks: any = await SecurityGuard({ client: {}, directory: ROOT, worktree: ROOT })

// A second live root gets a deterministic sibling log; the read hook must
// recognise that sibling as ITS active log, not the first root's.
const ROOT_B = mkdtempSync(join(tmpdir(), "sg-sens-root-b-"))
const hooksB: any = await SecurityGuard({ client: {}, directory: ROOT_B, worktree: ROOT_B })
const logB = getProjectContext(ROOT_B)?.logFile

const events = (): any[] =>
    readFileSync(LOG, "utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l))

test("sensitive-canonical: an innocent-named link to `.env` is sensitive", { skip: SKIP_FILE_LINK }, () => {
    const link = makeFileLink(join(ROOT, ".env"), "notes-link-env.txt")
    assert.equal(isSensitivePathFor(scope, link), true)
})

test("sensitive-canonical: a link into `.security-guard/**` is sensitive", () => {
    const link = join(ROOT, "state-link")
    linkDir(join(ROOT, ".security-guard"), link)
    assert.equal(isSensitivePathFor(scope, join(link, "blacklist")), true)
})

test("sensitive-canonical: a link to the active log is sensitive", { skip: SKIP_FILE_LINK }, () => {
    const link = makeFileLink(LOG, "log-link.txt")
    assert.equal(isSensitivePathFor(scope, link), true)
})

test("sensitive-canonical: an ordinary in-root link to a plain file is allowed", { skip: SKIP_FILE_LINK }, async () => {
    const link = makeFileLink(join(ROOT, "ok.txt"), "ok-link.txt")
    assert.equal(isSensitivePathFor(scope, link), false)
    await assert.doesNotReject(() =>
        hooks["tool.execute.before"](
            { tool: "write", sessionID: "s", callID: "c" },
            { args: { filePath: link, content: "plain text" } },
        ),
    )
})

test("sensitive-canonical: reading through the link is blocked in block mode", { skip: SKIP_FILE_LINK }, async () => {
    const link = makeFileLink(join(ROOT, ".env"), "read-link-env.txt")
    const n = events().filter((e) => e.event === "blocked.read").length
    await assert.rejects(
        () => hooks["tool.execute.before"]({ tool: "read", sessionID: "s", callID: "c" }, { args: { filePath: link } }),
        /sensitive file/,
    )
    const ev = events()
        .filter((e) => e.event === "blocked.read")
        .slice(n)
    assert.equal(ev.length, 1)
    assert.ok(!JSON.stringify(ev).includes(SECRET), "the raw secret must not reach the log")
})

test("sensitive-canonical: writing through the link is blocked before rehydration", {
    skip: SKIP_FILE_LINK,
}, async () => {
    const link = makeFileLink(join(ROOT, ".env"), "write-link-env.txt")
    await assert.rejects(
        () =>
            hooks["tool.execute.before"](
                { tool: "write", sessionID: "s", callID: "c" },
                { args: { filePath: link, content: "plain text" } },
            ),
        /sensitive file/,
    )
})

test("sensitive-canonical: a sensitive-named link to an innocent file stays sensitive", {
    skip: SKIP_FILE_LINK,
}, () => {
    const link = makeFileLink(join(ROOT, "ok.txt"), "id_rsa")
    assert.equal(isSensitivePathFor(scope, link), true)
})

test("sensitive-canonical: empty inputs are never sensitive", () => {
    assert.equal(isSensitivePathFor(scope, ""), false)
    assert.equal(isSensitivePathFor(scope, undefined), false)
    assert.equal(isSensitivePath(""), false)
})

test("sensitive-canonical: a second root's own log is blocked on read", async () => {
    assert.ok(logB, "no captured log for the second root")
    assert.notEqual(logB, LOG, "the second root must not share the first root's log")
    assert.equal(isSensitivePathFor({ logFile: logB, root: ROOT_B }, logB), true)
    await assert.rejects(
        () =>
            hooksB["tool.execute.before"]({ tool: "read", sessionID: "s", callID: "c" }, { args: { filePath: logB } }),
        /sensitive file/,
        "the second root's active log must be sensitive for its own read hook",
    )
})

test("sensitive-canonical: an uninspectable root fails closed", () => {
    const doomed = mkdtempSync(join(tmpdir(), "sg-sens-doomed-"))
    rmSync(doomed, { recursive: true, force: true })
    const scope = { logFile: LOG, root: doomed }
    assert.equal(isSensitivePathFor(scope, join(doomed, "notes.txt")), true)
})
