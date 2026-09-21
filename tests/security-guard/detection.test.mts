// Detection regression suite for expand-secret-detection.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/detection.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { loadGuard } from "./extract.mts"
import { createVault } from "../../src/vault.ts"

const g: Record<string, any> = await loadGuard()
const { scan, MARKER, INDICATOR } = g
const redacted = (s: string): boolean => scan(s).text !== s
const rulesHit = (s: string): string[] => scan(s).hits.map((h: any) => h.rule)
const mk = (rule: string, hash = "0123456789abcdef"): string => `<${MARKER}:${rule}:${hash}>`

// Deterministic mixed alphanumeric generator (no literal secrets in this file).
const rnd = (n: number): string => {
    const lower = "abcdefghijklmnopqrstuvwxyz"
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    const digit = "0123456789"
    let out = ""
    for (let i = 0; i < n; i++) {
        const pool = i % 3 === 0 ? upper : i % 3 === 1 ? lower : digit
        out += pool[(i * 7 + 3) % pool.length]
    }
    return out
}
const rhex = (n: number): string => "0123456789abcdef".repeat(8).slice(0, n)
const UUID = "123e4567-e89b-12d3-a456-426614174000"
const AWS = "AKIA" + "A1B2C3D4E5F6G7H8"

// ── 4.1 curated provider corpus ──────────────────────────────────────────
test("provider corpus: each new rule is redacted with its own name", () => {
    const cases: Array<[string, string]> = [
        ["gitlab-pat", `glpat-${rnd(20)}`],
        ["npm-token", `npm_${rnd(36)}`],
        ["pypi-token", `pypi-${rnd(36)}`],
        ["twilio-key", `SK${rhex(32)}`],
        ["sendgrid-key", `SG.${rnd(22)}.${rnd(43)}`],
        ["mailgun-key", `key-${rhex(32)}`],
        ["discord-bot-token", `M${rnd(23)}.${rnd(6)}.${rnd(27)}`],
        ["digitalocean-token", `dop_v1_${rhex(64)}`],
        ["shopify-token", `shpat_${rhex(32)}`],
        ["telegram-bot-token", `1234567890:${rnd(35)}`],
        ["anthropic-key", `sk-ant-api03-${rnd(30)}`],
        ["openai-key", `sk-${rnd(40)}`],
        ["huggingface-token", `hf_${rnd(34)}`],
        ["google-oauth-token", `ya29.${rnd(30)}`],
        ["azure-storage-key", `AccountKey=${rnd(86)}==`],
    ]
    for (const [name, value] of cases) {
        const r = scan(value)
        assert.ok(r.text !== value, `should redact ${name}`)
        assert.ok(
            r.hits.some((h: any) => h.rule === name),
            `expected ${name}, got ${rulesHit(value)}`,
        )
    }
})

test("provider lookalikes and bare UUIDs are not redacted", () => {
    // Short-prefix lookalikes (too short for the exact-length rule) must stay.
    const keep = [
        `glpat-${rnd(5)}`,
        `sk-${rnd(10)}`,
        `hf_${rnd(10)}`,
        `SK${rhex(31)}`,
        `key-${rhex(31)}`,
        `npm_${rnd(10)}`,
        `dop_v1_${rhex(10)}`,
        `shpat_${rhex(10)}`,
        `AIza${rnd(10)}`,
        `ya29.${rnd(10)}`,
        `SG.${rnd(10)}.${rnd(10)}`,
        `AccountKey=${rnd(10)}==`,
        `M${rnd(10)}.${rnd(6)}.${rnd(10)}`,
        `pypi-${rnd(10)}`,
        `1234567890:${rnd(10)}`,
        UUID,
        `heroku ${UUID.slice(0, 8)}`,
    ]
    for (const v of keep) assert.ok(!redacted(v), `should not redact: ${v}`)
})

test("Telegram token with _/- in the 35-char body is redacted", () => {
    // Full [A-Za-z0-9_-] character class of the body: separators must not
    // escape the INDICATOR pre-filter (regression: the token used to leak).
    const token = `1234567890:ABC_def-ghiJKLmnopqrstuvwxyz0123456`
    const r = scan(token)
    assert.ok(r.text !== token, "telegram token with separators must be redacted")
    assert.ok(
        r.hits.some((h: any) => h.rule === "telegram-bot-token"),
        `expected telegram-bot-token, got ${rulesHit(token)}`,
    )
})

test("exact-length boundaries: len_max+1 values stay unchanged (pinned policy)", () => {
    // 11 exact-length provider rules are pinned as fixed-length: an over-length
    // value is NOT assumed to be a valid provider token (conservative policy,
    // scanner-property-tests change). A future widening needs provider evidence
    // and a separate scope review. Each row is an explicit expected negative.
    const over: Array<[string, string]> = [
        ["aws-access-key", `AKIA${rnd(17).toUpperCase()}`], // 16 → 17 body chars
        ["gitlab-pat", `glpat-${rnd(21)}`], // 20 → 21
        ["twilio-key", `SK${rhex(33)}`], // 32 → 33
        ["mailgun-key", `key-${rhex(33)}`], // 32 → 33
        ["discord-bot-token", `M${rnd(24)}.${rnd(6)}.${rnd(27)}`], // first segment 23 → 24
        ["digitalocean-token", `dop_v1_${rhex(65)}`], // 64 → 65
        ["shopify-token", `shpat_${rhex(33)}`], // 32 → 33
        ["telegram-bot-token", `1234567890:${rnd(36)}`], // body 35 → 36
        [
            "license-token",
            `${rnd(5).toUpperCase()}-${rnd(5).toUpperCase()}-${rnd(5).toUpperCase()}-${rnd(5).toUpperCase()}-${rnd(5).toUpperCase()}${rnd(1).toUpperCase()}`,
        ], // 29 → 30
        ["hw-fingerprint", `ABCD-EFAB-CDAB-EFCD-ABEF:CDEF-0123-4567-89AB-CDEF:`], // 49 → 50 (10 groups; ':' breaks the 6-group chain)
        ["heroku-api-key", `heroku api_key ${UUID}a`], // 36 → 37
    ]
    for (const [name, value] of over) {
        const r = scan(value)
        assert.equal(r.text, value, `${name} len_max+1 must stay unchanged`)
        assert.equal(r.hits.length, 0, `${name} len_max+1 must not hit`)
    }
})

test("Heroku key requires keyword context", () => {
    assert.ok(redacted(`heroku api_key ${UUID}`), "contextual Heroku key")
    assert.ok(!redacted(UUID), "bare UUID must stay untouched")
})

test("JSON credential fields redact prefixed and provider-specific keys", () => {
    const config = JSON.stringify({
        mcp: {
            context7: { headers: { Authorization: "Bearer custom-bearer-token-123456" } },
            qdrant: { environment: { QDRANT_API_KEY: "qdrant-custom-token-123456" } },
        },
        providers: {
            crofai: { options: { apiKey: "nahcrof_custom_token_123456" } },
            inferx: { options: { apiKey: "ix_custom_token_123456" } },
            openrouter: { options: { apiKey: "sk-or-v1-custom-token-123456" } },
        },
    })
    const result = scan(config)
    assert.notEqual(result.text, config, "credential fields must be redacted")
    for (const value of [
        "custom-bearer-token-123456",
        "qdrant-custom-token-123456",
        "nahcrof_custom_token_123456",
        "ix_custom_token_123456",
        "sk-or-v1-custom-token-123456",
    ]) {
        assert.ok(!result.text.includes(value), `secret value leaked: ${value}`)
    }
    assert.ok(result.hits.filter((h: any) => h.rule === "credential-field").length >= 4)
})

// ── 4.2 encoded-secret detection ─────────────────────────────────────────
const pctEncode = (s: string): string => [...s].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")

test("encoded secrets are detected (base64/hex/percent)", () => {
    const cases: Array<[string, string]> = [
        ["base64", Buffer.from(AWS).toString("base64")],
        ["hex", Buffer.from(AWS).toString("hex")],
        ["percent", pctEncode(AWS)],
    ]
    for (const [label, enc] of cases) {
        const r = scan(enc)
        assert.ok(r.text !== enc, `should redact ${label}`)
        assert.ok(
            r.hits.some((h: any) => h.rule === "encoded-secret"),
            `${label} hit`,
        )
    }
})

test("encoded candidate is scanned without plaintext indicators", () => {
    const pct = pctEncode(AWS)
    assert.ok(!INDICATOR.test(pct), "percent form has no plaintext indicator")
    assert.ok(redacted(pct), "still decoded and redacted")
})

test("encoded non-secret is not redacted", () => {
    const hex = Buffer.from("this is not a secret at all").toString("hex")
    assert.ok(!redacted(hex), "ordinary hex text")
})

test("encoded span round-trips through the vault", () => {
    const b64 = Buffer.from(AWS).toString("base64")
    const r = scan(b64)
    const hit = r.hits.find((h: any) => h.rule === "encoded-secret")
    assert.ok(hit, "encoded hit present")
    assert.equal(hit.value, b64, "vault value is the encoded span, not the decoded secret")
    const vault = createVault()
    vault.store(hit.fp, hit.value)
    assert.equal(vault.lookup(hit.fp), b64, "write-back restores the encoded blob")
})

test("decoded value never enters hits or output", () => {
    const b64 = Buffer.from(AWS).toString("base64")
    const r = scan(b64)
    assert.ok(r.hits.length > 0, "encoded secret detected")
    for (const h of r.hits) assert.ok(!String(h.value).includes(AWS), "decoded secret in a hit")
    assert.ok(!r.text.includes(AWS), "decoded secret in output text")
})

// ── 4.3 allowlist ────────────────────────────────────────────────────────
test("allowlist: exact examples stay, substrings do not suppress", () => {
    assert.ok(!redacted("AKIA" + "IOSFODNN7EXAMPLE"), "AWS docs example")
    assert.ok(redacted(AWS), "real AWS key")
    assert.ok(redacted("AKIA" + "SAMPLE1234567890"), "secret containing 'sample' must be redacted")
})

// ── 4.4 bounds ───────────────────────────────────────────────────────────
test("bounds: low-entropy skipped, volume capped, no recursion", () => {
    assert.ok(!redacted("a".repeat(40)), "low-entropy run is not a candidate")

    const enc = Buffer.from(AWS).toString("base64")
    const many = Array.from({ length: 20 }, () => enc).join(" ")
    const encodedHits = scan(many).hits.filter((h: any) => h.rule === "encoded-secret")
    assert.ok(encodedHits.length > 0 && encodedHits.length <= 16, `cap applied, got ${encodedHits.length}`)

    const double = Buffer.from(Buffer.from(AWS).toString("hex")).toString("hex")
    assert.ok(!redacted(double), "double-encoded stays (single pass, no recursion)")
})

// ── 4.5 negative fixtures ────────────────────────────────────────────────
test("negative fixtures: hashes, samples and placeholders are untouched", () => {
    const keep = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        Buffer.from("not a secret").toString("base64"),
        "example.com",
        "placeholder",
        "your_api_key_here",
        UUID,
        "/etc/ssl/certs/x.pem",
        mk("jwt"),
    ]
    for (const v of keep) assert.ok(!redacted(v), `false positive: ${v.slice(0, 24)}`)
})
