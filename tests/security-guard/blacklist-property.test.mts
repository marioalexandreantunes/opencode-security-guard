// security-guard blacklist property suite — fuzz/property backlog P0.1.
// Deterministic PRNG, no external dependency.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/blacklist-property.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-blprop-log-")), "guard.log")

const { createBlacklist } = await import("../../src/blacklist.ts")
const { MARKER, fp } = await import("../../src/config.ts")
const { scan } = await import("../../src/rules.ts")

/** mulberry32: tiny deterministic PRNG so a failure reproduces from the seed. */
function rng(seed: number): () => number {
    let a = seed >>> 0
    return () => {
        a = (a + 0x6d2b79f5) >>> 0
        let t = Math.imul(a ^ (a >>> 15), 1 | a)
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296
    }
}
const pick = <T,>(r: () => number, xs: T[]): T => xs[Math.floor(r() * xs.length)]
const randCase = (r: () => number, s: string): string =>
    [...s].map((c) => (r() < 0.5 ? c.toUpperCase() : c.toLowerCase())).join("")

const DIR = mkdtempSync(join(tmpdir(), "sg-blprop-"))
let counter = 0
const writeList = (content: string): string => {
    const path = join(DIR, `blacklist-${counter++}`)
    writeFileSync(path, content, "utf8")
    return path
}

const HEX = [..."0123456789abcdef"]
const ALPHA = [..."abcdefghijklmnopqrstuvwxyz0123456789-"]

test("property: every casing is redacted with the observed fingerprint", () => {
    const r = rng(1337)
    for (let i = 0; i < 200; i++) {
        const length = 4 + Math.floor(r() * 12)
        let term = ""
        for (let j = 0; j < length; j++) term += pick(r, ALPHA)
        term = `t${term}`
        const bl = createBlacklist({ path: writeList(`${term}\n`) })
        const observed = randCase(r, term)
        const result = bl.apply(scan(`pre ${observed} post`))
        assert.equal(result.text, `pre <${MARKER}:blacklist:${fp(observed)}> post`, `term=${term} observed=${observed}`)
        assert.equal(result.hits[0]?.fp, fp(observed), "fingerprint must use the observed match")
        assert.equal(result.hits[0]?.value, observed, "the vault value must be the observed match")
    }
})

test("property: terms never match inside an existing marker", () => {
    const r = rng(2024)
    const rules = ["secret-assignment", "blacklist", "jwt", "entropy-blob"]
    for (let i = 0; i < 200; i++) {
        const hash = Array.from({ length: 16 }, () => pick(r, HEX)).join("")
        const rule = pick(r, rules)
        const markerText = `<${MARKER}:${rule}:${hash}>`
        const term = pick(r, [MARKER, "blacklist", "REDACTED", hash, rule, String(i)])
        const bl = createBlacklist({ path: writeList(`${term}\n`) })
        const result = bl.apply(scan(`prefix ${markerText} suffix`))
        assert.ok(result.text.includes(markerText), `marker damaged for term=${term}: ${result.text}`)
    }
})

test("property: ordinary text never produces a hit", () => {
    const r = rng(7)
    const words = ["alpha", "beta", "gamma", "report", "deploy", "service", "config", "build", "release"]
    const bl = createBlacklist({ path: writeList("ZuluTerm\nre:[0-9]{3}-[0-9]{3}\n") })
    for (let i = 0; i < 200; i++) {
        const length = 1 + Math.floor(r() * 8)
        const text = Array.from({ length }, () => pick(r, words)).join(" ")
        const result = bl.apply(scan(text))
        assert.equal(result.text, text, `false positive on: ${text}`)
        assert.deepEqual(result.hits, [])
    }
})
