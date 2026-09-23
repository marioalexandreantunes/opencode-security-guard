// security-guard blacklist suite (team-blacklist).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/blacklist.test.mts

import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-blacklist-log-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { createBlacklist } = await import("../../src/blacklist.ts")
const { MARKER, fp, norm } = await import("../../src/config.ts")
const { scan } = await import("../../src/rules.ts")

const DIR = mkdtempSync(join(tmpdir(), "sg-blacklist-"))
let counter = 0

/** Writes a fresh blacklist file and returns its path. */
function list(content: string): string {
    const path = join(DIR, `blacklist-${counter++}`)
    writeFileSync(path, content, "utf8")
    return path
}

const marker = (term: string): string => `<${MARKER}:blacklist:${fp(term)}>`
const logText = (): string => {
    try {
        return readFileSync(LOG, "utf8")
    } catch {
        return ""
    }
}
/** Parsed log records, tolerant of a torn trailing line. */
const parseRecords = (text: string): any[] =>
    text
        .split("\n")
        .map((line) => {
            try {
                return JSON.parse(line)
            } catch {
                return null
            }
        })
        .filter(Boolean)
/** Records written after `offset` characters, so a test can scope its own run. */
const parseEventsSince = (offset = 0): any[] => parseRecords(logText().slice(offset))
/**
 * Finds an event record by name and path. Fails with the paths that were
 * actually seen instead of dereferencing `undefined` when the lookup misses
 * (the Windows symptom: the record exists but under a normalized path).
 */
function eventByPath(events: any[], name: string, path: string): any {
    const wanted = norm(path)
    const found = events.find((e) => e?.event === name && e.path === wanted)
    assert.ok(
        found,
        `no ${name} record for ${wanted} — saw: ${
            events
                .filter((e) => e?.event === name)
                .map((e) => e.path)
                .join(", ") || "(none)"
        }`,
    )
    return found
}

// ─────────────────────────────────────────────────────────────────────────────
// Grammar
test("blacklist: a literal line matches case-insensitively as a substring", () => {
    const bl = createBlacklist({ path: list("# comment\n\nAcmeSecret\n") })
    assert.equal(bl.size, 1)
    const result = bl.apply(scan("prefix acmesECRET suffix"))
    assert.equal(result.text, `prefix ${marker("acmesECRET")} suffix`)
    const hit = result.hits.find((h: { rule: string }) => h.rule === "blacklist")
    assert.ok(hit, "no blacklist hit")
    assert.equal(hit.fp, fp("acmesECRET"))
    assert.equal(hit.value, "acmesECRET")
})

test("blacklist: comments and blank lines produce no terms", () => {
    const bl = createBlacklist({ path: list("# just a comment\n\n   \n# another\n") })
    assert.equal(bl.size, 0)
    assert.equal(bl.apply(scan("nothing to see")).text, "nothing to see")
})

test("blacklist: a re: line is ignored and remaining literal terms load", () => {
    const path = list("re:acme-[0-9]{4}\nKeepMe\n")
    const bl = createBlacklist({ path })
    assert.equal(bl.size, 1)
    const result = bl.apply(scan("ref ACME-1234 keepme"))
    assert.equal(result.text, `ref ACME-1234 ${marker("keepme")}`)
    const log = logText()
    assert.match(log, /"event":"blacklist.invalid"/)
    assert.match(log, /"error":"unsupported-pattern"/)
    assert.ok(!log.includes("acme-[0-9]{4}"), "the unsupported pattern leaked into the log")
})

test("blacklist: an adversarial re: line is ignored without blocking", () => {
    const child = spawnSync(
        process.execPath,
        [
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            `
                import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"
                import { tmpdir } from "node:os"
                import { join } from "node:path"
                process.env.SECURITY_GUARD_PROJECT_DIR = "0"
                const log = join(mkdtempSync(join(tmpdir(), "sg-redos-log-")), "guard.log")
                process.env.SECURITY_GUARD_LOG = log
                const { createBlacklist } = await import("./src/blacklist.ts")
                const path = join(mkdtempSync(join(tmpdir(), "sg-redos-")), "blacklist")
                const pattern = "re:^(a+)+$"
                writeFileSync(path, pattern + "\\nKeepMe\\n", "utf8")
                const blacklist = createBlacklist({ path })
                const input = "a".repeat(10000) + "!"
                const result = blacklist.apply({ text: input, hits: [] })
                const logged = readFileSync(log, "utf8")
                if (blacklist.size !== 1 || result.text !== input || logged.includes(pattern)) {
                    console.error("blacklist regression failed")
                    process.exitCode = 1
                }
            `,
        ],
        { cwd: process.cwd(), env: { ...process.env }, encoding: "utf8", timeout: 5000 },
    )
    assert.ok(!child.error, "blacklist child timed out or failed to spawn")
    assert.equal(child.status, 0, "blacklist regression failed")
})

test("blacklist: a backtracking-looking re: line is skipped and logged without the pattern", () => {
    const path = list("re:(unclosed\nKeepMe\n")
    const bl = createBlacklist({ path })
    assert.equal(bl.size, 1, "the valid term must still load")
    assert.ok(bl.apply(scan("keepme")).text.includes(marker("keepme")))
    const log = logText()
    assert.match(log, /"level":"warn"/)
    assert.match(log, /"event":"blacklist.invalid"/)
    assert.match(log, /"line":1/)
    assert.match(log, /"error":"unsupported-pattern"/)
    assert.ok(!log.includes("unclosed"), "the re: pattern leaked into the log")
})

test("blacklist: empty re: lines are skipped and logged as unsupported", () => {
    const path = list("re:\nre:   \nKeepMe\n")
    const bl = createBlacklist({ path })
    assert.equal(bl.size, 1)
    const log = logText()
    assert.match(log, /"level":"warn"/)
    assert.match(log, /"event":"blacklist.invalid"/)
    assert.match(log, /"error":"unsupported-pattern"/)
    assert.match(log, /"line":1/)
    assert.match(log, /"line":2/)
})

test("blacklist: a scan with no match is returned by identity", () => {
    const bl = createBlacklist({ path: list("AcmeC0de\n") })
    const input = scan("nothing to hide")
    assert.equal(bl.apply(input), input)
})

test("blacklist: whitespace around an unsupported re: line is trimmed", () => {
    const bl = createBlacklist({ path: list("re:  acme-[0-9]{4}  \n") })
    assert.equal(bl.size, 0)
    assert.equal(bl.apply(scan("ACME-0042")).text, "ACME-0042")
    assert.match(logText(), /"error":"unsupported-pattern"/)
    assert.ok(!logText().includes("acme-[0-9]{4}"), "the unsupported pattern leaked into the log")
})

test("blacklist: a missing file yields an empty list without errors", () => {
    const path = join(DIR, "does-not-exist")
    const before = logText().length
    const bl = createBlacklist({ path })
    assert.equal(bl.size, 0)
    assert.equal(bl.refresh(), false)
    assert.equal(bl.apply(scan("clean text")).text, "clean text")
    const events = parseEventsSince(before)
    const loaded = eventByPath(events, "blacklist.loaded", path)
    assert.equal(loaded.level, "info")
    assert.equal(loaded.count, 0)
    assert.equal(loaded.path, norm(path))
    assert.ok(!events.some((e) => e.error === "read-failed"), "a missing file must not log a read failure")
    assert.ok(!events.some((e) => e.event === "blacklist.invalid"))
})

test("blacklist: a null path disables matching", () => {
    const bl = createBlacklist({ path: null })
    assert.equal(bl.size, 0)
    assert.equal(bl.refresh(true), false)
    assert.equal(bl.apply(scan("anything")).text, "anything")
})

test("blacklist: an empty path disables matching", () => {
    const bl = createBlacklist({ path: "" })
    assert.equal(bl.size, 0)
    assert.equal(bl.refresh(true), false)
    assert.equal(bl.apply(scan("anything")).text, "anything")
})

test("blacklist: non-string or empty scan text is returned unchanged", () => {
    const bl = createBlacklist({ path: list("AcmeC0de\n") })
    const empty = { text: "", hits: [] }
    assert.equal(bl.apply(empty), empty)
    const notString = { text: 123, hits: [] }
    assert.equal(bl.apply(notString as never), notString)
})

// ─────────────────────────────────────────────────────────────────────────────
// Observed value and marker protection
test("blacklist: the marker hash is derived from the observed casing", () => {
    const bl = createBlacklist({ path: list("AcmeSecret\n") })
    for (const observed of ["acmesecret", "ACMESECRET", "AcMeSeCrEt"]) {
        const result = bl.apply(scan(observed))
        assert.equal(result.text, marker(observed), `casing: ${observed}`)
        assert.equal(result.hits[0].fp, fp(observed))
        assert.equal(result.hits[0].value, observed)
    }
})

test("blacklist: literal metacharacters do not become regex syntax", () => {
    const bl = createBlacklist({ path: list("acme-[0-9]{4}\n") })
    const result = bl.apply(scan("ref acme-[0-9]{4} and ACME-2026 ok"))
    assert.equal(result.text, `ref ${marker("acme-[0-9]{4}")} and ACME-2026 ok`)
    assert.equal(result.hits.length, 1)
    assert.equal(result.hits[0].value, "acme-[0-9]{4}")
})

test("blacklist: repeated occurrences of one literal reuse its marker", () => {
    const bl = createBlacklist({ path: list("Acme-2025\n") })
    const result = bl.apply(scan("acme-2025 then acme-2025 again"))
    assert.equal(result.text, `${marker("acme-2025")} then ${marker("acme-2025")} again`)
    assert.equal(result.hits.length, 2)
    for (const hit of result.hits) {
        assert.equal(hit.fp, fp("acme-2025"))
        assert.equal(hit.value, "acme-2025")
    }
})

test("blacklist: terms never match inside an existing marker", () => {
    const bl = createBlacklist({ path: list("REDACTED\nblacklist\n") })
    const existing = `<${MARKER}:secret-assignment:0123456789abcdef>`
    const result = bl.apply(scan(`x ${existing} y`))
    assert.equal(result.text, `x ${existing} y`)
    assert.deepEqual(result.hits, [])
})

test("blacklist: unsupported re: lines cannot create empty matches", () => {
    const bl = createBlacklist({ path: list("re:x*\n") })
    assert.equal(bl.size, 0)
    const result = bl.apply(scan("abc"))
    assert.equal(result.text, "abc")
    assert.deepEqual(result.hits, [])
})

test("blacklist: secret and blacklist hits are combined", () => {
    const bl = createBlacklist({ path: list("AcmeC0de\n") })
    const secret = "api_key=" + "Xy9kQ2mN7vR4tW8zB5c"
    const result = bl.apply(scan(`${secret} on AcmeC0de`))
    assert.ok(result.hits.some((h: { rule: string }) => h.rule === "secret-assignment" || h.rule === "bare-credential"))
    assert.ok(result.hits.some((h: { rule: string }) => h.rule === "blacklist"))
    assert.ok(result.text.includes(marker("AcmeC0de")))
})

// ─────────────────────────────────────────────────────────────────────────────
// Hot reload
test("blacklist: an unchanged file is not re-read", () => {
    const path = list("Alpha\n")
    const bl = createBlacklist({ path, ttlMs: 0 })
    assert.equal(bl.refresh(), false)
    assert.equal(bl.refresh(), false)
})

test("blacklist: a changed file is reloaded and the new terms apply", () => {
    const path = list("Alpha\n")
    const bl = createBlacklist({ path, ttlMs: 0 })
    writeFileSync(path, "Beta\n", "utf8")
    assert.equal(bl.refresh(), true)
    assert.equal(bl.apply(scan("Beta")).text, marker("Beta"))
    assert.equal(bl.apply(scan("alpha")).text, "alpha", "the old term must be gone")
    const reloaded = eventByPath(parseEventsSince(), "blacklist.reloaded", path)
    assert.equal(reloaded.level, "info")
    assert.equal(reloaded.count, 1)
    assert.equal(reloaded.version, 2)
    assert.equal(reloaded.path, norm(path))
})

test("blacklist: a deleted file empties the list on reload", () => {
    const path = list("Zeta\n")
    const bl = createBlacklist({ path, ttlMs: 0 })
    rmSync(path)
    assert.equal(bl.refresh(), true)
    assert.equal(bl.size, 0)
    const reloaded = eventByPath(parseEventsSince(), "blacklist.reloaded", path)
    assert.equal(reloaded.count, 0)
    assert.equal(reloaded.version, 2, "the deletion must bump the version")
})

test("blacklist: a read failure keeps the previous list active", () => {
    const path = list("Gamma\n")
    const bl = createBlacklist({ path, ttlMs: 0 })
    rmSync(path)
    mkdirSync(path) // a directory at the file path makes readFileSync throw
    assert.equal(bl.refresh(), false)
    assert.equal(bl.size, 1, "the previous term must be retained")
    assert.match(bl.apply(scan("Gamma")).text, /blacklist/)
    const event = eventByPath(parseEventsSince(), "blacklist.reloaded", path)
    assert.equal(event.level, "warn")
    assert.equal(event.error, "read-failed")
    assert.equal(event.count, 1, "the retained term count must be logged")
})

test("blacklist: ttl -1 disables reload until forced", () => {
    const path = list("Delta\n")
    const bl = createBlacklist({ path, ttlMs: -1 })
    writeFileSync(path, "Epsilon 123\n", "utf8")
    assert.equal(bl.refresh(), false)
    assert.equal(bl.apply(scan("epsilon 123")).text, "epsilon 123")
    assert.equal(bl.refresh(true), true)
    assert.equal(bl.apply(scan("epsilon 123")).text, marker("epsilon 123"))
})

test("blacklist: an invalid TTL env falls back to the default", () => {
    const previous = process.env.SECURITY_GUARD_BLACKLIST_TTL_MS
    process.env.SECURITY_GUARD_BLACKLIST_TTL_MS = "not-a-number"
    try {
        const path = list("Theta\n")
        const bl = createBlacklist({ path })
        writeFileSync(path, "Iota 123\n", "utf8")
        assert.equal(bl.refresh(), false, "the default TTL must throttle the reload")
    } finally {
        if (previous === undefined) delete process.env.SECURITY_GUARD_BLACKLIST_TTL_MS
        else process.env.SECURITY_GUARD_BLACKLIST_TTL_MS = previous
    }
})

test("blacklist: a whitespace-only TTL env falls back to the default", () => {
    const previous = process.env.SECURITY_GUARD_BLACKLIST_TTL_MS
    process.env.SECURITY_GUARD_BLACKLIST_TTL_MS = "   "
    try {
        const path = list("Lambda 123\n")
        const bl = createBlacklist({ path })
        writeFileSync(path, "Mu 123\n", "utf8")
        assert.equal(bl.refresh(), false, "the default TTL must throttle the reload")
        assert.equal(bl.apply(scan("mu 123")).text, "mu 123", "the file must not be reloaded yet")
    } finally {
        if (previous === undefined) delete process.env.SECURITY_GUARD_BLACKLIST_TTL_MS
        else process.env.SECURITY_GUARD_BLACKLIST_TTL_MS = previous
    }
})

test("blacklist: clear empties the compiled terms", () => {
    const bl = createBlacklist({ path: list("Kappa\n") })
    assert.equal(bl.size, 1)
    bl.clear()
    assert.equal(bl.size, 0)
    assert.equal(bl.apply(scan("Kappa")).text, "Kappa")
    assert.equal(bl.refresh(true), false)
})

// ─────────────────────────────────────────────────────────────────────────────
// No term leaks into logs
test("blacklist: load events carry counts and version, never the terms", () => {
    const unique = "HighlySensitiveCodename77"
    createBlacklist({ path: list(`${unique}\nre:${unique}-[0-9]+\n`) })
    assert.ok(!logText().includes(unique), "a term leaked into the log")
})
