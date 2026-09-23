// security-guard canonical destination boundary unit suite: the project root
// and every write destination are compared canonically (links followed), new
// files resolve through the nearest existing ancestor, and uninspectable
// destinations fail closed. Synthetic temp fixtures only.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/write-policy-canonical.test.mts

import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { basename, join } from "node:path"
import { test } from "node:test"
import { fileLinkSkipReason, linkDir, linkFile } from "./platform-fixtures.mts"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-canon-log-")), "guard.log")

const { classifyDestination, resolveCanonicalTarget, canonicalizeRoot, isInsideWorktree } = await import(
    "../../src/write-policy.ts"
)

const ROOT = mkdtempSync(join(tmpdir(), "sg-canon-root-"))
const OUTSIDE = mkdtempSync(join(tmpdir(), "sg-canon-out-"))
writeFileSync(join(ROOT, "inside.txt"), "inside\n")
writeFileSync(join(OUTSIDE, "secret.txt"), "outside\n")
mkdirSync(join(ROOT, "sub"), { recursive: true })

// A denied Windows file-symlink privilege skips only the dependent scenario.
const SKIP_FILE_LINK = fileLinkSkipReason()

test("canonical: an existing in-root file is inside", () => {
    assert.equal(classifyDestination(ROOT, join(ROOT, "inside.txt")).verdict, "inside")
})

test("canonical: a new in-root file below a real directory is inside", () => {
    assert.equal(classifyDestination(ROOT, join(ROOT, "sub", "new.txt")).verdict, "inside")
})

test("canonical: a `..` traversal that stays inside is inside", () => {
    assert.equal(classifyDestination(ROOT, join(ROOT, "sub", "..", "inside.txt")).verdict, "inside")
})

test("canonical: a `..` traversal that escapes the root is outside", () => {
    const escaped = join(ROOT, "..", basename(OUTSIDE), "secret.txt")
    assert.equal(classifyDestination(ROOT, escaped).verdict, "outside")
})

test("canonical: an existing symlink to an external file is outside", { skip: SKIP_FILE_LINK }, () => {
    const evilLink = join(ROOT, "evil-link.txt")
    linkFile(join(OUTSIDE, "secret.txt"), evilLink)
    const verdict = classifyDestination(ROOT, evilLink).verdict
    assert.equal(verdict, "outside")
    assert.equal(isInsideWorktree(ROOT, evilLink), true, "lexical check alone is blind to the link")
})

test("canonical: a new file below a linked directory is outside", () => {
    const linkedDir = join(ROOT, "linked-dir")
    linkDir(OUTSIDE, linkedDir)
    assert.equal(classifyDestination(ROOT, join(linkedDir, "new.txt")).verdict, "outside")
})

test("canonical: an uninspectable root fails closed", () => {
    const doomed = mkdtempSync(join(tmpdir(), "sg-canon-doomed-"))
    rmSync(doomed, { recursive: true, force: true })
    assert.equal(canonicalizeRoot(doomed), null)
    assert.equal(classifyDestination(doomed, "x.txt").verdict, "unverifiable")
    assert.ok(
        resolveCanonicalTarget(doomed, "x.txt")?.endsWith(join(basename(doomed), "x.txt")),
        "the target still resolves through the nearest existing ancestor; the missing root is what fails closed",
    )
})

test("canonical: a junction to an external directory is outside", () => {
    const link = join(ROOT, "junction-link")
    linkDir(OUTSIDE, link)
    assert.equal(classifyDestination(ROOT, link).verdict, "outside")
})

test("canonical: the canonical root is stable and absolute", () => {
    const root = canonicalizeRoot(ROOT)
    assert.ok(root, "an existing root must canonicalize")
    assert.equal(root, realpathSync.native(ROOT))
})

test("canonical: empty and root-itself targets are inside", () => {
    assert.deepEqual(classifyDestination(ROOT, ""), {
        verdict: "inside",
        canonicalRoot: null,
        canonicalTarget: null,
    })
    const rootTarget = classifyDestination(ROOT, ROOT)
    assert.equal(rootTarget.verdict, "inside")
    assert.equal(rootTarget.canonicalRoot, realpathSync.native(ROOT))
    assert.equal(rootTarget.canonicalTarget, realpathSync.native(ROOT))
})
