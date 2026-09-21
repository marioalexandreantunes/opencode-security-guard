// security-guard project-directory bootstrap suite (project-directory).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/project-dir.test.mts
import { beforeEach, test } from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const SAFE_LOG = join(mkdtempSync(join(tmpdir(), "sg-projdir-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = SAFE_LOG

const cfg = await import("../../src/config.ts")
const { bootstrapProjectDir, bootstrapErrorCode, SECURITY_GUARD_DIR } = await import("../../src/project-dir.ts")
const { logProbe } = await import("./log-probe.mts")
const probe = logProbe(cfg.writeLog)

// The shipped content is pinned here as literals on purpose: importing the
// source constant would compare against the mutated value and never fail.
const IGNORE_BLOCK =
    "# security-guard (project-local state)\n" +
    "/.security-guard/*\n" +
    "!/.security-guard/blacklist.example\n" +
    "!/.security-guard/halt.example\n"
const EXAMPLE_TEXT =
    "# security-guard team blacklist (example)\n" +
    "#\n" +
    '# Copy this file to "blacklist" and declare one term per line. Terms are\n' +
    "# matched case-insensitively as substrings and redacted before inference.\n" +
    "#\n" +
    "# Lines starting with # are comments; blank lines are ignored.\n" +
    '# A line prefixed with "re:" is compiled as a case-insensitive regular\n' +
    "# expression (an invalid one is skipped and logged). Any other term is\n" +
    "# literal: regex metacharacters (e.g. *) are not wildcards.\n" +
    "#\n" +
    "# Examples:\n" +
    "# AcmeProjectCodename\n" +
    "# internal.acme.example\n" +
    "# re:acme-[0-9]{4}\n" +
    "# re:apikey_[0-9a-f]+(?:_[0-9a-f]+)*\n"
const HALT_EXAMPLE_TEXT =
    "plugin disabled\n" +
    "\n" +
    "# security-guard halt (example)\n" +
    "#\n" +
    '# Copy this file to "halt" to disable security-guard in this project.\n' +
    "# The plugin only checks that the file exists; the first line above is\n" +
    '# informational. Delete "halt" to re-enable the guard.\n'

const ROOTS = mkdtempSync(join(tmpdir(), "sg-projdir-"))
let counter = 0
const newRoot = (): string => {
    const root = join(ROOTS, `root-${counter++}`)
    mkdirSync(root, { recursive: true })
    return root
}
const logText = (): string => {
    try {
        return readFileSync(SAFE_LOG, "utf8")
    } catch {
        return ""
    }
}
const parseLog = (): Array<Record<string, any>> =>
    logText()
        .split("\n")
        .map((line) => {
            try {
                return JSON.parse(line)
            } catch {
                return null
            }
        })
        .filter((e): e is Record<string, any> => e !== null)

beforeEach(() => {
    process.env.SECURITY_GUARD_LOG = SAFE_LOG
    cfg.setLogFile(SAFE_LOG)
})

// ─────────────────────────────────────────────────────────────────────────────
test("project-dir: creates the directory and the blacklist example", () => {
    const root = newRoot()
    const result = bootstrapProjectDir(root)
    const dir = join(root, SECURITY_GUARD_DIR)
    assert.ok(existsSync(dir), "directory not created")
    assert.equal(result.dir, dir)
    assert.equal(result.created, true)
    assert.equal(result.example, true)
    const example = readFileSync(join(dir, "blacklist.example"), "utf8")
    assert.equal(example, EXAMPLE_TEXT, "the example content must be pinned exactly")
    assert.match(example, /^#/m, "the example must document comments")
    assert.match(example, /re:/, "the example must document the re: prefix")
    assert.equal(result.haltExample, true)
    const halt = readFileSync(join(dir, "halt.example"), "utf8")
    assert.equal(halt, HALT_EXAMPLE_TEXT, "the halt example content must be pinned exactly")
    assert.ok(halt.startsWith("plugin disabled\n"), "the halt example must open with the disabled marker line")
    assert.match(logText(), /"event":"project-dir\.ready"/)
    assert.match(logText(), /"level":"info"/)
    // Parse the record instead of interpolating the raw path: the log is JSON, so a
    // Windows root is escaped (`C:\\...`) and a raw `includes(root)` would never match.
    const ready = parseLog().find((e) => e.event === "project-dir.ready")
    assert.ok(ready, "no project-dir.ready event")
    assert.equal(ready.root, cfg.norm(root), "the ready event must carry the normalized root")
})

test("project-dir: the second run is idempotent and preserves existing files", () => {
    const root = newRoot()
    writeFileSync(join(root, ".gitignore"), "node_modules/\n", "utf8")
    const first = bootstrapProjectDir(root)
    assert.equal(first.ignored, true, "the first run must report the directory ignored")
    const example = join(root, SECURITY_GUARD_DIR, "blacklist.example")
    const custom = "# team-owned example\nDoNotOverwrite\n"
    writeFileSync(example, custom, "utf8")
    const haltExample = join(root, SECURITY_GUARD_DIR, "halt.example")
    const customHalt = "plugin disabled\nkeep me\n"
    writeFileSync(haltExample, customHalt, "utf8")

    const second = bootstrapProjectDir(root)

    assert.equal(second.example, false, "the second run must not report a written example")
    assert.equal(second.haltExample, false, "the second run must not report a written halt example")
    assert.equal(second.ignored, true)
    assert.equal(readFileSync(example, "utf8"), custom, "the example was overwritten")
    assert.equal(readFileSync(haltExample, "utf8"), customHalt, "the halt example was overwritten")
    const lines = readFileSync(join(root, ".gitignore"), "utf8").split("\n")
    assert.equal(lines.filter((l) => l === "/.security-guard/*").length, 1, "the ignore block was appended twice")
    assert.ok(lines.includes("!/.security-guard/blacklist.example"), "the negation is missing")
})

test("project-dir: upgrades an existing generated ignore block for halt.example", () => {
    const root = newRoot()
    const existing =
        "# security-guard (project-local state)\n" + "/.security-guard/*\n" + "!/.security-guard/blacklist.example\n"
    writeFileSync(join(root, ".gitignore"), existing, "utf8")

    bootstrapProjectDir(root)

    assert.equal(readFileSync(join(root, ".gitignore"), "utf8"), `${existing}!/.security-guard/halt.example\n`)
})

test("project-dir: the ignore block is byte-exact for every .gitignore shape", () => {
    const cases: Array<{ name: string; existing: string; expected: string }> = [
        { name: "empty file", existing: "", expected: IGNORE_BLOCK },
        { name: "trailing newline", existing: "node_modules/\n", expected: `node_modules/\n${IGNORE_BLOCK}` },
        { name: "no trailing newline", existing: "node_modules/", expected: `node_modules/\n${IGNORE_BLOCK}` },
        { name: "starts with newline", existing: "\nfoo", expected: `\nfoo\n${IGNORE_BLOCK}` },
    ]
    for (const c of cases) {
        const root = newRoot()
        writeFileSync(join(root, ".gitignore"), c.existing, "utf8")
        const result = bootstrapProjectDir(root)
        assert.equal(result.ignored, true, c.name)
        assert.equal(readFileSync(join(root, ".gitignore"), "utf8"), c.expected, c.name)
    }
})

test("project-dir: a legacy .security-guard/ line is treated as already ignored", () => {
    const root = newRoot()
    writeFileSync(join(root, ".gitignore"), "node_modules/\n.security-guard/\n", "utf8")
    const result = bootstrapProjectDir(root)
    assert.equal(result.ignored, true)
    assert.equal(readFileSync(join(root, ".gitignore"), "utf8"), "node_modules/\n.security-guard/\n")
})

test("project-dir: a whitespace-padded legacy line is treated as already ignored", () => {
    const root = newRoot()
    const content = "  .security-guard/  \n"
    writeFileSync(join(root, ".gitignore"), content, "utf8")
    const result = bootstrapProjectDir(root)
    assert.equal(result.ignored, true)
    assert.equal(readFileSync(join(root, ".gitignore"), "utf8"), content)
})

test("project-dir: a mid-line .security-guard reference still appends the block", () => {
    const root = newRoot()
    const existing = "node_modules/.security-guard/\n"
    writeFileSync(join(root, ".gitignore"), existing, "utf8")
    const result = bootstrapProjectDir(root)
    assert.equal(result.ignored, true)
    assert.equal(readFileSync(join(root, ".gitignore"), "utf8"), `${existing}${IGNORE_BLOCK}`)
})

test("project-dir: a VCS worktree gets a root .gitignore when missing", () => {
    const root = newRoot()
    mkdirSync(join(root, ".git"))
    const result = bootstrapProjectDir(root)
    assert.equal(result.ignored, true)
    const ignore = readFileSync(join(root, ".gitignore"), "utf8")
    assert.equal(ignore, IGNORE_BLOCK)
    assert.match(ignore, /^# security-guard \(project-local state\)$/m)
    assert.match(ignore, /^\/\.security-guard\/\*$/m)
    assert.match(ignore, /^!\/\.security-guard\/blacklist\.example$/m)
    assert.match(ignore, /^!\/\.security-guard\/halt\.example$/m)
})

test("project-dir: outside a VCS worktree the directory ignores itself", () => {
    const root = newRoot()
    const result = bootstrapProjectDir(root)
    assert.equal(result.ignored, true)
    assert.ok(!existsSync(join(root, ".gitignore")), "no root .gitignore may be created")
    assert.equal(readFileSync(join(root, SECURITY_GUARD_DIR, ".gitignore"), "utf8"), "*\n")
})

test("project-dir: a nested root whose parent is missing is created recursively", () => {
    const nested = join(ROOTS, `nested-${counter++}`, "child")
    const result = bootstrapProjectDir(nested)
    assert.equal(result.created, true, "recursive mkdir must create the missing parent")
    assert.ok(existsSync(join(nested, SECURITY_GUARD_DIR)), "the nested directory was not created")
})

test("project-dir: the log moves into the project directory", () => {
    const root = newRoot()
    delete process.env.SECURITY_GUARD_LOG
    const result = bootstrapProjectDir(root)
    assert.equal(cfg.LOG_FILE, join(root, SECURITY_GUARD_DIR, "security-guard.log"))
    assert.equal(result.log, join(root, SECURITY_GUARD_DIR, "security-guard.log"))
    probe("info", "project-dir.test-marker")
    assert.match(readFileSync(cfg.LOG_FILE, "utf8"), /project-dir\.test-marker/)
})

test("project-dir: an explicit SECURITY_GUARD_LOG wins over the project log", () => {
    const root = newRoot()
    const result = bootstrapProjectDir(root)
    assert.equal(cfg.LOG_FILE, SAFE_LOG)
    assert.equal(result.log, SAFE_LOG)
})

test("project-dir: opts.relocateLog=false keeps the previous log", () => {
    const root = newRoot()
    delete process.env.SECURITY_GUARD_LOG
    const result = bootstrapProjectDir(root, { relocateLog: false })
    assert.equal(cfg.LOG_FILE, SAFE_LOG)
    assert.equal(result.log, SAFE_LOG)
})

test("project-dir: an unwritable root fails open and falls back", () => {
    const fileRoot = join(ROOTS, `file-root-${counter++}`)
    writeFileSync(fileRoot, "i am a file\n", "utf8")
    delete process.env.SECURITY_GUARD_LOG
    const result = bootstrapProjectDir(fileRoot)
    assert.equal(result.log, SAFE_LOG, "a failed bootstrap must keep the previous log")
    assert.equal(result.created, false, "a failed mkdir must leave created false")
    assert.equal(result.ignored, false, "a failed gitignore step must leave ignored false")
    assert.equal(result.example, false, "a failed example write must leave example false")
    assert.equal(cfg.LOG_FILE, SAFE_LOG, "the previous log must be kept")
    const codes: Record<string, string> = {
        directory: "mkdir-failed",
        gitignore: "write-failed",
        "blacklist.example": "write-failed",
        "halt.example": "write-failed",
    }
    const failed = parseLog().filter((e) => e.event === "project-dir.failed")
    for (const step of ["directory", "gitignore", "blacklist.example", "halt.example"]) {
        const event = failed.find((e) => e.step === step)
        assert.ok(event, `no project-dir.failed for step ${step}`)
        assert.equal(event.level, "warn")
        assert.equal(event.error, codes[step], `step ${step} must carry its stable code`)
        assert.ok(!JSON.stringify(event).includes(fileRoot), `step ${step} must not log the absolute path`)
        assert.ok(!JSON.stringify(event).includes("Error:"), `step ${step} must not log the engine message`)
    }
})

test("project-dir: bootstrap error codes cover every step and fallback", () => {
    assert.equal(bootstrapErrorCode("directory"), "mkdir-failed")
    assert.equal(bootstrapErrorCode("gitignore"), "write-failed")
    assert.equal(bootstrapErrorCode("blacklist.example"), "write-failed")
    assert.equal(bootstrapErrorCode("halt.example"), "write-failed")
    assert.equal(bootstrapErrorCode("log"), "write-failed")
    assert.equal(bootstrapErrorCode("unknown-step"), "io-error")
})
