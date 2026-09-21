// security-guard hermeticity suite: PROJECT_DIR=0 must leave no project state,
// while an explicit SECURITY_GUARD_BLACKLIST still loads (team-blacklist).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/project-dir-disabled.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const ROOT = mkdtempSync(join(tmpdir(), "sg-projoff-"))
const LOG_TMP = join(mkdtempSync(join(tmpdir(), "sg-projoff-log-")), "guard.log")
const BLACKLIST = join(mkdtempSync(join(tmpdir(), "sg-projoff-bl-")), "blacklist")
const TERM = "ExplicitTeamTerm"
writeFileSync(BLACKLIST, `${TERM}\n`, "utf8")

process.env.SECURITY_GUARD_LOG = LOG_TMP
process.env.SECURITY_GUARD_PROJECT_DIR = "0"
process.env.SECURITY_GUARD_BLACKLIST = BLACKLIST

const { SecurityGuard } = await import("../../src/index.ts")
const cfg = await import("../../src/config.ts")
const { fp, MARKER } = cfg

const hooks = await SecurityGuard({ client: {}, directory: ROOT, worktree: ROOT })

test("hermetic: PROJECT_DIR=0 creates no .security-guard/ and touches no .gitignore", () => {
    assert.ok(!existsSync(join(ROOT, ".security-guard")), "a project directory was created")
    assert.ok(!existsSync(join(ROOT, ".gitignore")), "a root .gitignore was created")
    assert.equal(cfg.LOG_FILE, LOG_TMP, "the log must not be relocated")
})

test("explicit SECURITY_GUARD_BLACKLIST loads with the bootstrap disabled", async () => {
    const output: Record<string, any> = { parts: [{ type: "text", text: `leak ${TERM} here` }] }
    await hooks["chat.message"]({}, output)
    const text = String(output.parts[0].text)
    assert.ok(text.includes(`<${MARKER}:blacklist:${fp(TERM)}>`), "the term was not redacted")
    assert.ok(!text.includes(TERM), "the raw term leaked")
})
