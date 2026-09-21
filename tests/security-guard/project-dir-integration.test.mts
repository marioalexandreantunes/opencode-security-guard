// security-guard integration suite for the project directory (bootstrap ON).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/project-dir-integration.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { appendFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// Hermetic by construction: temp project root, temp log. The bootstrap must be
// ON, so the setup-env kill-switch is removed before the factory runs and the
// explicit log is removed so the log can be relocated into the project.
const ROOT = mkdtempSync(join(tmpdir(), "sg-projint-"))
const LOG_TMP = join(mkdtempSync(join(tmpdir(), "sg-projint-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG_TMP
delete process.env.SECURITY_GUARD_PROJECT_DIR
delete process.env.SECURITY_GUARD_BLACKLIST
process.env.SECURITY_GUARD_BLACKLIST_TTL_MS = "0"

const { SecurityGuard } = await import("../../src/index.ts")
const cfg = await import("../../src/config.ts")
const { isSensitivePath } = await import("../../src/paths.ts")
const { fp, MARKER } = cfg
delete process.env.SECURITY_GUARD_LOG

const hooks = await SecurityGuard({ client: {}, directory: ROOT, worktree: "/" })

const DIR = join(ROOT, ".security-guard")
const BLACKLIST = join(DIR, "blacklist")
const TERM = "AcmeC0dename"
const PATTERN = "acme-[0-9]{4}"
// The file is written after bootstrap (the directory must exist first); the TTL
// of 0 makes the next hook pick the terms up and clear the scan cache.
writeFileSync(BLACKLIST, `# team terms\n${TERM}\nre:${PATTERN}\n`, "utf8")

const mk = (term: string): string => `<${MARKER}:blacklist:${fp(term)}>`
const instanceLog = (): string => {
    const file = cfg.getProjectContext(ROOT)?.logFile
    assert.ok(file, "no instance context for the project root")
    return file
}
const projectLog = (): string => readFileSync(instanceLog(), "utf8")

// ─────────────────────────────────────────────────────────────────────────────
test("integration: the directory is created at the resolved root", () => {
    assert.ok(existsSync(DIR), "no project directory")
    assert.ok(existsSync(join(DIR, "blacklist.example")))
    assert.ok(existsSync(join(DIR, ".gitignore")), "non-VCS root must self-ignore")
    assert.equal(instanceLog(), join(DIR, "security-guard.log"))
    assert.match(projectLog(), /"event":"project-dir\.ready"/)
})

test("integration: a term in the prompt is redacted with the observed marker", async () => {
    const output: Record<string, any> = { parts: [{ type: "text", text: `about ${TERM} and acme-1234` }] }
    await hooks["chat.message"]({}, output)
    const text = String(output.parts[0].text)
    assert.ok(text.includes(mk(TERM)), "literal term not redacted")
    assert.ok(text.includes(mk("acme-1234")), "re: term not redacted")
    assert.ok(!text.includes(TERM), "the raw term leaked")
    assert.ok(!text.includes("acme-1234"), "the raw regex match leaked")
})

test("integration: a different casing produces the observed marker", async () => {
    const output: Record<string, any> = { parts: [{ type: "text", text: "mentions ACMEC0DENAME here" }] }
    await hooks["chat.message"]({}, output)
    assert.ok(String(output.parts[0].text).includes(mk("ACMEC0DENAME")))
    assert.ok(!String(output.parts[0].text).includes("ACMEC0DENAME"))
})

test("integration: the system prompt is redacted", async () => {
    const output: Record<string, any> = { system: [`system rules for ${TERM}`] }
    await hooks["experimental.chat.system.transform"]({}, output)
    const text = String(output.system.join(" "))
    assert.ok(text.includes(mk(TERM)))
    assert.ok(!text.includes(TERM))
})

test("integration: the message history is redacted", async () => {
    const output: Record<string, any> = {
        messages: [{ info: { role: "user" }, parts: [{ type: "text", text: `history keeps ${TERM}` }] }],
    }
    await hooks["experimental.chat.messages.transform"]({}, output)
    const text = String(output.messages[0].parts[0].text)
    assert.ok(text.includes(mk(TERM)))
    assert.ok(!text.includes(TERM))
})

test("integration: tool output is redacted", async () => {
    const output: Record<string, any> = { output: `tool said ${TERM}`, metadata: { note: TERM } }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, output)
    assert.ok(!String(output.output).includes(TERM), "output leaked")
    assert.ok(!JSON.stringify(output.metadata).includes(TERM), "metadata leaked")
    assert.ok(String(output.output).includes(mk(TERM)))
})

test("integration: a known blacklist marker rehydrates on write", async () => {
    const args: Record<string, any> = { filePath: join(ROOT, "note.txt"), content: `value=${mk(TERM)}` }
    await hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args })
    assert.equal(args.content, `value=${TERM}`)
})

test("integration: two regex values rehydrate independently on write", async () => {
    const first = "acme-2025"
    const second = "ACME-2026"
    const output: Record<string, any> = { output: `codes ${first} and ${second}`, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, output)
    const text = String(output.output)
    assert.ok(text.includes(mk(first)), "first value not redacted")
    assert.ok(text.includes(mk(second)), "second value not redacted")
    assert.ok(!text.includes(first), "first raw value leaked")
    assert.ok(!text.includes(second), "second raw value leaked")
    const args: Record<string, any> = { filePath: join(ROOT, "codes.txt"), content: `a=${mk(first)} b=${mk(second)}` }
    await hooks["tool.execute.before"]({ tool: "write", sessionID: "s", callID: "c" }, { args })
    assert.equal(args.content, `a=${first} b=${second}`)
})

test("integration: the log carries markers but no blacklist values", async () => {
    const log = projectLog()
    assert.ok(!log.includes(TERM), "declared literal leaked into the log")
    assert.ok(!log.includes(PATTERN), "re: declaration leaked into the log")
    assert.ok(!log.includes("ACMEC0DENAME"), "observed casing leaked into the log")
    assert.ok(!log.includes("acme-1234"), "observed regex match leaked into the log")
})

test("integration: .security-guard/** is a sensitive path", async () => {
    assert.ok(isSensitivePath(join(DIR, "blacklist")))
    await assert.rejects(
        () =>
            hooks["tool.execute.before"](
                { tool: "write", sessionID: "s", callID: "c" },
                { args: { filePath: join(DIR, "blacklist"), content: "tamper" } },
            ),
        /sensitive file/,
    )
    await assert.rejects(
        () =>
            hooks["tool.execute.before"](
                { tool: "bash", sessionID: "s", callID: "c" },
                { args: { command: "cat .security-guard/blacklist" } },
            ),
        /sensitive file/,
    )
})

test("integration: a blacklist reload invalidates the scan cache", async () => {
    const first: Record<string, any> = { parts: [{ type: "text", text: "ProjectZeta stays clean" }] }
    await hooks["chat.message"]({}, first)
    assert.equal(first.parts[0].text, "ProjectZeta stays clean", "precondition: cached as clean")

    appendFileSync(BLACKLIST, "ProjectZeta\n", "utf8")

    const second: Record<string, any> = { parts: [{ type: "text", text: "ProjectZeta stays clean" }] }
    await hooks["chat.message"]({}, second)
    assert.ok(String(second.parts[0].text).includes(mk("ProjectZeta")), "the stale cache was reused")
})

test("integration: no blacklist term leaks into the project log", () => {
    const log = projectLog()
    assert.ok(!log.includes(TERM), "a term leaked into the log")
    assert.ok(!log.includes(PATTERN), "a re: pattern leaked into the log")
})
