// property-scanner.mts — property/fuzz suite over src/rules.ts (P-1…P-11).
//
// Run:   npm run test:property            (fixed default seed, ~5 s budget)
//        npm run test:property:nightly    (large counts, random seed, prints it)
// Replay: SG_FUZZ_SEED=<seed> npm run test:property
//
// This file deliberately does NOT match the `tests/**/*.test.mts` glob, so
// `npm test` (Stryker's command runner) and the c8 coverage gate are unaffected.

import assert from "node:assert/strict"
import { Buffer } from "node:buffer"
import { execFile } from "node:child_process"
import { readdirSync, readFileSync } from "node:fs"
import { mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import fc from "fast-check"
import { MARKER } from "../../src/config.ts"
import {
    createScanCache,
    entropy,
    INDICATOR,
    looksBare,
    looksReal,
    looksSecret,
    mixedBlob,
    RULES,
    scan,
    scanDeep,
} from "../../src/rules.ts"

// ── seed / run configuration ──────────────────────────────────────────────
const NIGHTLY = process.env.SG_FUZZ_NIGHTLY === "1"
const DEFAULT_SEED = 20260912
const SEED: number = process.env.SG_FUZZ_SEED
    ? Number(process.env.SG_FUZZ_SEED)
    : NIGHTLY
      ? Number(new Uint32Array(crypto.getRandomValues(new Uint32Array(1)))[0])
      : DEFAULT_SEED
const RUNS = NIGHTLY ? 5000 : 100

if (NIGHTLY && !process.env.SG_FUZZ_SEED) {
    console.error(`SG_FUZZ_SEED=${SEED} (nightly random seed; replay with SG_FUZZ_SEED=${SEED})`)
}

// ── property runner: prints seed + counterexample, then fails the test ─────
function runProperty(name: string, prop: fc.IProperty<[unknown, ...unknown[]]>, numRuns: number = RUNS): void {
    const details = fc.check(prop, { seed: SEED, numRuns })
    if (!details.failed) return
    const counterexample = details.counterexampleStringified ?? JSON.stringify(details.counterexample)
    console.error(`PROPERTY FAILED: ${name}`)
    console.error(`seed: ${details.seed}`)
    console.error(`counterexample: ${counterexample}`)
    if (details.errorInstance instanceof Error) console.error(`error: ${details.errorInstance.message}`)
    console.error(`repro: SG_FUZZ_SEED=${details.seed} npm run test:property`)
    throw new Error(`property ${name} failed (seed ${details.seed})`)
}

// ── deterministic random access for the format generators ─────────────────
type Gen = { nextInt(min: number, max: number): number }

const toGen = (g: (arb: unknown, constraints?: unknown) => unknown): Gen => ({
    nextInt: (min, max) => (g(fc.nat, { max: max - min }) as number) + min,
})

function makeRng(seed: number): () => number {
    let state = (BigInt(seed) ^ 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn
    const next = (): number => {
        state = (state + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn
        let z = state
        z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn
        z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn
        z = z ^ (z >> 31n)
        return Number(z & 0xffffffffn)
    }
    return next
}

const rngGen = (rng: () => number): Gen => ({ nextInt: (min, max) => min + (rng() % (max - min + 1)) })

// ── character pools and string helpers ────────────────────────────────────
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const ALNUMU = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const HEX = "0123456789abcdef"
const HEXU = "0123456789ABCDEF"
const SEP = "_-"
const B64URL = ALNUM + SEP

const pick = (g: Gen, pool: string): string => pool[g.nextInt(0, pool.length - 1)]
const str = (g: Gen, pool: string, n: number): string => {
    let out = ""
    for (let i = 0; i < n; i++) out += pick(g, pool)
    return out
}
const alnum = (g: Gen, n: number): string => str(g, ALNUM, n)
const alnumUpper = (g: Gen, n: number): string => str(g, ALNUMU, n)
const hex = (g: Gen, n: number): string => str(g, HEX, n)
const hexUpper = (g: Gen, n: number): string => str(g, HEXU, n)
const sepAlnum = (g: Gen, n: number): string => str(g, B64URL, n)
const digits = (g: Gen, n: number): string => str(g, "0123456789", n)
// Like sepAlnum but guarantees a word-character ending: rules whose regex
// finishes with `\b` after a class that includes "-" do not match a trailing
// dash (e.g. `glpat-…-`), so the last char must be [A-Za-z0-9_].
const sepAlnumEnd = (g: Gen, n: number): string => (n <= 1 ? "" : sepAlnum(g, n - 1)) + pick(g, `${ALNUM}_`)
// Rejection-sample on payload entropy: real provider tokens are random, and
// the encoded path (P-11) only redacts candidates at or above its 2.0 entropy
// floor, so a degenerate all-same-char payload would not be a realistic
// instance of a provider format (the plaintext rule still catches it raw).
const realistic = (g: Gen, pool: string, n: number, min = 2.6): string => {
    let s = ""
    do {
        s = str(g, pool, n)
    } while (entropy(s) < min)
    return s
}
const realisticEnd = (g: Gen, n: number): string => {
    let s = realistic(g, B64URL, n)
    if (s.endsWith("-")) s = `${s.slice(0, -1)}${pick(g, `${ALNUM}_`)}`
    return s
}

// ── format specs (one per rule) ───────────────────────────────────────────
// `gen` produces a full trigger input plus the payload `scan()` should capture.
// `overrun` produces the len_max+1 value used by the boundary sweep (pinned
// rules only). `short` produces a len_min-1 value where that is well-defined.
type Format = {
    name: string
    gen: (g: Gen) => { input: string; payload: string }
    overrun?: (g: Gen) => string
    short?: (g: Gen) => string
}

const uuid = (g: Gen): string => `${hex(g, 8)}-${hex(g, 4)}-${hex(g, 4)}-${hex(g, 4)}-${hex(g, 12)}`

const FORMATS: Record<string, Format> = {
    "obfuscated-string": {
        name: "obfuscated-string",
        gen: (g) => {
            // Rejection-sample so the payload passes the looksSecret gate (a
            // zero-entropy run like all-A would not be a detected secret).
            let payload = ""
            do {
                payload = alnum(g, g.nextInt(16, 40))
            } while (!looksSecret(payload))
            return { input: `obfstr!("${payload}")`, payload }
        },
    },
    "license-token": {
        name: "license-token",
        gen: (g) => {
            // Whole-payload rejection sample: a single 5-char group cannot
            // reach the 2.6 entropy floor (max log2(5) ≈ 2.32).
            let payload = ""
            do {
                payload = Array.from({ length: 5 }, () => alnumUpper(g, 5)).join("-")
            } while (entropy(payload) < 2.6)
            return { input: payload, payload }
        },
        overrun: (g) => Array.from({ length: 5 }, () => alnumUpper(g, 5)).join("-") + alnumUpper(g, 1),
        short: (g) => Array.from({ length: 4 }, () => alnumUpper(g, 5)).join("-"),
    },
    "hw-fingerprint": {
        name: "hw-fingerprint",
        gen: (g) => {
            const groups = 6 + g.nextInt(0, 4)
            // Whole-payload rejection sample: a single 4-char group cannot
            // reach the 2.6 entropy floor (max log2(4) = 2.0).
            let payload = ""
            do {
                payload = Array.from({ length: groups }, () => hexUpper(g, 4)).join("-")
            } while (entropy(payload) < 2.6)
            return { input: payload, payload }
        },
        // 50 chars: two runs of 5 groups — no 6-group chain, so the regex and
        // the INDICATOR both stay silent (pinned policy: len_max+1 → unchanged).
        overrun: (g) => {
            const run = () => Array.from({ length: 5 }, () => hexUpper(g, 4)).join("-")
            return `${run()}:${run()}:`
        },
        short: (g) => Array.from({ length: 5 }, () => hexUpper(g, 4)).join("-"),
    },
    "aws-access-key": {
        name: "aws-access-key",
        gen: (g) => {
            const payload = `AKIA${realistic(g, ALNUMU, 16)}`
            return { input: payload, payload }
        },
        overrun: (g) => `AKIA${alnumUpper(g, 17)}`,
        short: (g) => `AKIA${alnumUpper(g, 15)}`,
    },
    "aws-secret-key": {
        name: "aws-secret-key",
        gen: (g) => {
            const payload = realistic(g, ALNUM, 40)
            return { input: `secret_key = "${payload}"`, payload }
        },
    },
    "github-token": {
        name: "github-token",
        gen: (g) => {
            const payload = `ghp_${realistic(g, ALNUM, g.nextInt(36, 48))}`
            return { input: payload, payload }
        },
    },
    "slack-token": {
        name: "slack-token",
        gen: (g) => {
            // The rule class is [A-Za-z0-9-] (no underscore) and ends with \b,
            // so the last char must be alphanumeric (no trailing dash).
            const n = g.nextInt(10, 24)
            const payload = `xoxb-${realistic(g, `${ALNUM}-`, n - 1)}${pick(g, ALNUM)}`
            return { input: payload, payload }
        },
    },
    "stripe-key": {
        name: "stripe-key",
        gen: (g) => {
            const payload = `sk_live_${realistic(g, ALNUM, g.nextInt(24, 40))}`
            return { input: payload, payload }
        },
    },
    "google-api-key": {
        name: "google-api-key",
        gen: (g) => {
            const payload = `AIza${realisticEnd(g, 35)}`
            return { input: payload, payload }
        },
    },
    "gitlab-pat": {
        name: "gitlab-pat",
        gen: (g) => {
            const payload = `glpat-${realisticEnd(g, 20)}`
            return { input: payload, payload }
        },
        overrun: (g) => `glpat-${sepAlnum(g, 21)}`,
        short: (g) => `glpat-${sepAlnum(g, 19)}`,
    },
    "npm-token": {
        name: "npm-token",
        gen: (g) => {
            const payload = `npm_${realistic(g, ALNUM, 36)}`
            return { input: payload, payload }
        },
    },
    "pypi-token": {
        name: "pypi-token",
        gen: (g) => {
            const payload = `pypi-${realisticEnd(g, g.nextInt(34, 44))}`
            return { input: payload, payload }
        },
    },
    "twilio-key": {
        name: "twilio-key",
        gen: (g) => {
            const payload = `SK${realistic(g, HEX, 32)}`
            return { input: payload, payload }
        },
        overrun: (g) => `SK${hex(g, 33)}`,
        short: (g) => `SK${hex(g, 31)}`,
    },
    "sendgrid-key": {
        name: "sendgrid-key",
        gen: (g) => {
            const payload = `SG.${realistic(g, B64URL, 22)}.${realisticEnd(g, 43)}`
            return { input: payload, payload }
        },
    },
    "mailgun-key": {
        name: "mailgun-key",
        gen: (g) => {
            const payload = `key-${realistic(g, HEX, 32)}`
            return { input: payload, payload }
        },
        overrun: (g) => `key-${hex(g, 33)}`,
        short: (g) => `key-${hex(g, 31)}`,
    },
    "discord-bot-token": {
        name: "discord-bot-token",
        gen: (g) => {
            // First segment class is [A-Za-z\d] (no underscore); the last
            // segment ends with \b so it must not end in "-". Whole-payload
            // rejection sample: the 6-char middle segment alone cannot reach
            // the 2.6 entropy floor (max log2(6) ≈ 2.58).
            let payload = ""
            do {
                payload = `M${alnum(g, 23)}.${sepAlnum(g, 6)}.${sepAlnumEnd(g, g.nextInt(27, 38))}`
            } while (entropy(payload) < 2.6)
            return { input: payload, payload }
        },
        overrun: (g) => `M${sepAlnum(g, 24)}.${sepAlnum(g, 6)}.${sepAlnum(g, 27)}`,
        short: (g) => `M${sepAlnum(g, 22)}.${sepAlnum(g, 6)}.${sepAlnum(g, 27)}`,
    },
    "digitalocean-token": {
        name: "digitalocean-token",
        gen: (g) => {
            const payload = `dop_v1_${realistic(g, HEX, 64)}`
            return { input: payload, payload }
        },
        overrun: (g) => `dop_v1_${hex(g, 65)}`,
        short: (g) => `dop_v1_${hex(g, 63)}`,
    },
    "shopify-token": {
        name: "shopify-token",
        gen: (g) => {
            const payload = `shpat_${realistic(g, HEX, 32)}`
            return { input: payload, payload }
        },
        overrun: (g) => `shpat_${hex(g, 33)}`,
        short: (g) => `shpat_${hex(g, 31)}`,
    },
    "telegram-bot-token": {
        name: "telegram-bot-token",
        gen: (g) => {
            const payload = `${digits(g, 8 + g.nextInt(0, 2))}:${realisticEnd(g, 35)}`
            return { input: payload, payload }
        },
        overrun: (g) => `1234567890:${sepAlnum(g, 36)}`,
        short: (g) => `1234567:${sepAlnum(g, 35)}`,
    },
    "anthropic-key": {
        name: "anthropic-key",
        gen: (g) => {
            const payload = `sk-ant-api03-${realisticEnd(g, g.nextInt(24, 36))}`
            return { input: payload, payload }
        },
    },
    "openai-key": {
        name: "openai-key",
        gen: (g) => {
            const payload =
                g.nextInt(0, 1) === 0
                    ? `sk-proj-${realisticEnd(g, g.nextInt(20, 36))}`
                    : `sk-${realistic(g, ALNUM, g.nextInt(32, 48))}`
            return { input: payload, payload }
        },
    },
    "huggingface-token": {
        name: "huggingface-token",
        gen: (g) => {
            const payload = `hf_${realistic(g, ALNUM, 34)}`
            return { input: payload, payload }
        },
    },
    "google-oauth-token": {
        name: "google-oauth-token",
        gen: (g) => {
            const payload = `ya29.${realisticEnd(g, g.nextInt(24, 40))}`
            return { input: payload, payload }
        },
    },
    "azure-storage-key": {
        name: "azure-storage-key",
        gen: (g) => {
            const payload = `${realistic(g, ALNUM, 86)}==`
            return { input: `AccountKey=${payload}`, payload }
        },
    },
    "heroku-api-key": {
        name: "heroku-api-key",
        gen: (g) => {
            let payload = ""
            do {
                payload = uuid(g)
            } while (entropy(payload) < 2.6)
            return { input: `heroku api_key ${payload}`, payload }
        },
        overrun: (g) => `heroku api_key ${uuid(g)}a`,
        short: (g) => `heroku api_key ${hex(g, 8)}-${hex(g, 4)}-${hex(g, 4)}-${hex(g, 4)}-${hex(g, 11)}`,
    },
    "gcp-service-account": {
        name: "gcp-service-account",
        gen: (g) => {
            const payload = `-----BEGIN PRIVATE KEY-----\n${realistic(g, ALNUM, 120)}\n-----END PRIVATE KEY-----\n`
            return { input: `"private_key": "${payload}"`, payload }
        },
    },
    "private-key-block": {
        name: "private-key-block",
        gen: (g) => {
            const payload = `-----BEGIN RSA PRIVATE KEY-----\n${realistic(g, ALNUM, 80)}\n-----END RSA PRIVATE KEY-----`
            return { input: payload, payload }
        },
    },
    jwt: {
        name: "jwt",
        gen: (g) => {
            const payload = `eyJ${realistic(g, B64URL, g.nextInt(8, 16))}.${realistic(g, B64URL, g.nextInt(8, 16))}.${realisticEnd(g, g.nextInt(8, 16))}`
            return { input: payload, payload }
        },
    },
    "db-connection-string": {
        name: "db-connection-string",
        gen: (g) => {
            const payload = realistic(g, ALNUM, g.nextInt(8, 16))
            return { input: `postgres://user:${payload}@host/db`, payload }
        },
    },
    "bearer-token": {
        name: "bearer-token",
        gen: (g) => {
            const payload = realistic(g, ALNUM, g.nextInt(20, 40))
            return { input: `Bearer ${payload}`, payload }
        },
    },
    "bare-credential": {
        name: "bare-credential",
        gen: (g) => {
            // Force at least one digit and rejection-sample on looksBare so the
            // value is a detected secret (low-entropy all-A runs are not).
            let payload = ""
            do {
                const body = alnum(g, g.nextInt(16, 32))
                payload = `${body.slice(0, -1)}${g.nextInt(0, 9)}`
            } while (!looksBare(payload))
            return { input: `api_key = ${payload}`, payload }
        },
    },
    "credential-field": {
        name: "credential-field",
        gen: (g) => {
            const payload = realistic(g, ALNUM, g.nextInt(16, 40))
            return { input: `{"apiKey":"${payload}"}`, payload }
        },
    },
    "entropy-blob": {
        name: "entropy-blob",
        gen: (g) => {
            // Rejection-sample on the src entropy (generation only; the P-6
            // oracle uses the independent reference implementation).
            let payload = ""
            do {
                payload = alnum(g, g.nextInt(40, 80))
            } while (entropy(payload) < 4.5)
            return { input: payload, payload }
        },
    },
    "secret-assignment": {
        name: "secret-assignment",
        gen: (g) => {
            // Spaces keep bare-credential (which runs first) from swallowing
            // the value: its class stops at whitespace, so the fragment is
            // shorter than its 16-char floor.
            const payload = `correct horse battery staple ${alnum(g, g.nextInt(8, 16))}`
            return { input: `password = "${payload}"`, payload }
        },
    },
    "base64-blob": {
        name: "base64-blob",
        gen: (g) => {
            // 32–39 chars: long enough for base64-blob, short enough that
            // entropy-blob (which runs first) cannot swallow it (40-char floor).
            // Rejection-sample on mixedBlob so the value is detected.
            let payload = ""
            do {
                payload = alnum(g, g.nextInt(32, 39))
            } while (!mixedBlob(payload))
            return { input: `"${payload}"`, payload }
        },
    },

    // ── adversarial corpus (add-adversarial-corpus): 18 provider formats ─────
    "aws-sts-key": {
        name: "aws-sts-key",
        gen: (g) => {
            const payload = `ASIA${realistic(g, ALNUMU, 16)}`
            return { input: payload, payload }
        },
    },
    "github-fine-grained-pat": {
        name: "github-fine-grained-pat",
        gen: (g) => {
            // Class [A-Za-z0-9_]; `\b` still holds when the body ends in "_".
            const payload = `github_pat_${realistic(g, `${ALNUM}_`, g.nextInt(40, 52))}`
            return { input: payload, payload }
        },
    },
    "slack-app-token": {
        name: "slack-app-token",
        gen: (g) => {
            // Class [A-Za-z0-9-] (no underscore) and `\b`: end alphanumeric.
            // A digit is required (validate): real tokens are xapp-<n>-…
            let payload = ""
            do {
                const n = g.nextInt(10, 24)
                payload = `xapp-${realistic(g, `${ALNUM}-`, n - 1)}${pick(g, ALNUM)}`
            } while (!/\d/.test(payload))
            return { input: payload, payload }
        },
    },
    "stripe-restricted-key": {
        name: "stripe-restricted-key",
        gen: (g) => {
            const payload = `rk_live_${realistic(g, ALNUM, g.nextInt(24, 40))}`
            return { input: payload, payload }
        },
    },
    "grafana-service-account-token": {
        name: "grafana-service-account-token",
        gen: (g) => {
            const payload = `glsa_${realistic(g, `${ALNUM}_`, g.nextInt(32, 44))}`
            return { input: payload, payload }
        },
    },
    "docker-pat": {
        name: "docker-pat",
        gen: (g) => {
            const payload = `dckr_pat_${realisticEnd(g, g.nextInt(26, 40))}`
            return { input: payload, payload }
        },
    },
    "vault-token": {
        name: "vault-token",
        gen: (g) => {
            const payload = `hvs.${realistic(g, ALNUM, g.nextInt(24, 40))}`
            return { input: payload, payload }
        },
    },
    "tailscale-key": {
        name: "tailscale-key",
        gen: (g) => {
            // A digit is required (validate): real keys are tskey-auth-…/api-…
            let payload = ""
            do {
                const n = g.nextInt(10, 24)
                payload = `tskey-${realistic(g, `${ALNUM}-`, n - 1)}${pick(g, ALNUM)}`
            } while (!/\d/.test(payload))
            return { input: payload, payload }
        },
    },
    "replicate-token": {
        name: "replicate-token",
        gen: (g) => {
            const payload = `r8_${realistic(g, ALNUM, 37)}`
            return { input: payload, payload }
        },
    },
    "groq-key": {
        name: "groq-key",
        gen: (g) => {
            const payload = `gsk_${realistic(g, ALNUM, 48)}`
            return { input: payload, payload }
        },
    },
    "xai-key": {
        name: "xai-key",
        gen: (g) => {
            const payload = `xai-${realistic(g, ALNUM, 80)}`
            return { input: payload, payload }
        },
    },
    "perplexity-key": {
        name: "perplexity-key",
        gen: (g) => {
            const payload = `pplx-${realistic(g, ALNUM, g.nextInt(30, 44))}`
            return { input: payload, payload }
        },
    },
    "pulumi-token": {
        name: "pulumi-token",
        gen: (g) => {
            const payload = `pul-${realistic(g, ALNUM, 40)}`
            return { input: payload, payload }
        },
    },
    "render-key": {
        name: "render-key",
        gen: (g) => {
            const payload = `rnd_${realistic(g, ALNUM, g.nextInt(40, 52))}`
            return { input: payload, payload }
        },
    },
    "doppler-token": {
        name: "doppler-token",
        gen: (g) => {
            // Official forms: dp.{st[,project]|pt|ct|said|sa}.<40–44>.
            const kinds = ["st", "pt", "ct", "said", "sa"]
            const kind = kinds[g.nextInt(0, kinds.length - 1)]
            const project =
                kind === "st" && g.nextInt(0, 1) === 1
                    ? `${str(g, "abcdefghijklmnopqrstuvwxyz0123456789_-", g.nextInt(2, 8))}.`
                    : ""
            const payload = `dp.${kind}.${project}${realistic(g, ALNUM, g.nextInt(40, 44))}`
            return { input: payload, payload }
        },
    },
    "resend-key": {
        name: "resend-key",
        gen: (g) => {
            const payload = `re_${realistic(g, `${ALNUM}_`, g.nextInt(30, 44))}`
            return { input: payload, payload }
        },
    },
    "brevo-key": {
        name: "brevo-key",
        gen: (g) => {
            const payload = `xkeysib-${realistic(g, ALNUM, g.nextInt(40, 52))}`
            return { input: payload, payload }
        },
    },
    "linear-key": {
        name: "linear-key",
        gen: (g) => {
            const payload = `lin_api_${realistic(g, ALNUM, g.nextInt(30, 44))}`
            return { input: payload, payload }
        },
    },
}

// ── P-2: plaintext pre-filter soundness (pure checker) ────────────────────
type RuleSample = { name: string; regex: RegExp; sample: () => string }

/** Returns the names of rules whose regex matches the sample but INDICATOR does not. */
function prefilterGaps(rules: RuleSample[]): string[] {
    const gaps: string[] = []
    for (const { name, regex, sample } of rules) {
        const s = sample()
        regex.lastIndex = 0
        INDICATOR.lastIndex = 0
        if (regex.test(s) && !INDICATOR.test(s)) gaps.push(name)
    }
    return gaps
}

test("P-2 self-test: a rule absent from INDICATOR is reported (the checker has teeth)", () => {
    const fake: RuleSample = {
        name: "fake-rule",
        regex: /fake_prefix_[A-Za-z0-9]{20}/g,
        sample: () => `fake_prefix_${alnum(rngGen(makeRng(1)), 20)}`,
    }
    const gaps = prefilterGaps([fake])
    assert.ok(gaps.includes("fake-rule"), `expected fake-rule to be reported, got ${gaps.join(",")}`)
})

test("P-2: every rule match is reachable through INDICATOR", () => {
    runProperty(
        "P-2 prefilter soundness",
        fc.property(fc.noShrink(fc.gen()), (g) => {
            const gen = toGen(g)
            const gaps = prefilterGaps(
                RULES.map((r) => ({ name: r.name, regex: r.regex, sample: () => FORMATS[r.name].gen(gen).input })),
            )
            assert.deepEqual(gaps, [], `rules skipped by the pre-filter: ${gaps.join(", ")}`)
        }),
    )
})

// ── P-1: per-rule true positives ──────────────────────────────────────────
test("P-1: every rule fires on its generated format (true positives)", () => {
    for (const rule of RULES) {
        const fmt = FORMATS[rule.name]
        assert.ok(fmt, `missing format spec for ${rule.name}`)
        runProperty(
            `P-1 ${rule.name}`,
            fc.property(fc.noShrink(fc.gen()), (g) => {
                const gen = toGen(g)
                const { input, payload } = fmt.gen(gen)
                const r = scan(input)
                const hit = r.hits.find((h) => h.rule === rule.name)
                assert.ok(hit, `expected ${rule.name} to fire on ${JSON.stringify(input).slice(0, 60)}`)
                assert.equal(hit.value, payload, `${rule.name}: hit payload must be the generated secret`)
            }),
        )
    }
})

// ── boundary sweep: exact-length rules (pinned policy) ────────────────────
// The 11 rules pinned as fixed-length in this change (see evidence.md): the
// len_max+1 value is an explicit expected negative, len_min-1 too where the
// rule has a meaningful minimum. Values are generated deterministically.
const PINNED_SWEEP: Array<{ name: string; make: (g: Gen) => string; redacted: boolean; label: string }> = [
    { name: "aws-access-key", label: "len_max+1", make: (g) => `AKIA${alnumUpper(g, 17)}`, redacted: false },
    { name: "aws-access-key", label: "len_min-1", make: (g) => `AKIA${alnumUpper(g, 15)}`, redacted: false },
    { name: "gitlab-pat", label: "len_max+1", make: (g) => `glpat-${sepAlnum(g, 21)}`, redacted: false },
    { name: "gitlab-pat", label: "len_min-1", make: (g) => `glpat-${sepAlnum(g, 19)}`, redacted: false },
    { name: "twilio-key", label: "len_max+1", make: (g) => `SK${hex(g, 33)}`, redacted: false },
    { name: "twilio-key", label: "len_min-1", make: (g) => `SK${hex(g, 31)}`, redacted: false },
    { name: "mailgun-key", label: "len_max+1", make: (g) => `key-${hex(g, 33)}`, redacted: false },
    { name: "mailgun-key", label: "len_min-1", make: (g) => `key-${hex(g, 31)}`, redacted: false },
    {
        name: "discord-bot-token",
        label: "len_max+1",
        make: (g) => `M${sepAlnum(g, 24)}.${sepAlnum(g, 6)}.${sepAlnum(g, 27)}`,
        redacted: false,
    },
    {
        name: "discord-bot-token",
        label: "len_min-1",
        make: (g) => `M${sepAlnum(g, 22)}.${sepAlnum(g, 6)}.${sepAlnum(g, 27)}`,
        redacted: false,
    },
    { name: "digitalocean-token", label: "len_max+1", make: (g) => `dop_v1_${hex(g, 65)}`, redacted: false },
    { name: "digitalocean-token", label: "len_min-1", make: (g) => `dop_v1_${hex(g, 63)}`, redacted: false },
    { name: "shopify-token", label: "len_max+1", make: (g) => `shpat_${hex(g, 33)}`, redacted: false },
    { name: "shopify-token", label: "len_min-1", make: (g) => `shpat_${hex(g, 31)}`, redacted: false },
    { name: "telegram-bot-token", label: "len_max+1", make: (g) => `1234567890:${sepAlnum(g, 36)}`, redacted: false },
    { name: "telegram-bot-token", label: "len_min-1", make: (g) => `1234567:${sepAlnum(g, 35)}`, redacted: false },
    {
        name: "license-token",
        label: "len_max+1",
        make: (g) => Array.from({ length: 5 }, () => alnumUpper(g, 5)).join("-") + alnumUpper(g, 1),
        redacted: false,
    },
    {
        name: "license-token",
        label: "len_min-1",
        make: (g) => Array.from({ length: 4 }, () => alnumUpper(g, 5)).join("-"),
        redacted: false,
    },
    {
        name: "hw-fingerprint",
        label: "len_max+1",
        make: (g) =>
            `${Array.from({ length: 5 }, () => hexUpper(g, 4)).join("-")}:${Array.from({ length: 5 }, () => hexUpper(g, 4)).join("-")}:`,
        redacted: false,
    },
    {
        name: "hw-fingerprint",
        label: "len_min-1",
        make: (g) => Array.from({ length: 5 }, () => hexUpper(g, 4)).join("-"),
        redacted: false,
    },
    { name: "heroku-api-key", label: "len_max+1", make: (g) => `heroku api_key ${uuid(g)}a`, redacted: false },
    {
        name: "heroku-api-key",
        label: "len_min-1",
        make: (g) => `heroku api_key ${hex(g, 8)}-${hex(g, 4)}-${hex(g, 4)}-${hex(g, 4)}-${hex(g, 11)}`,
        redacted: false,
    },
]

test("boundary sweep: len_max+1 and len_min-1 stay unchanged (pinned exact-length policy)", () => {
    const g = rngGen(makeRng(SEED ^ 0x5151))
    for (const { name, label, make, redacted } of PINNED_SWEEP) {
        const value = make(g)
        const r = scan(value)
        const got = r.text !== value
        assert.equal(
            got,
            redacted,
            `${name} ${label}: expected ${redacted ? "redacted" : "unchanged"}, got ${r.hits.map((h) => h.rule).join(",") || "unchanged"}`,
        )
    }
})

// ── P-3: marker stability ─────────────────────────────────────────────────
test("P-3: re-scanning a redacted output yields no further hits and unchanged text", () => {
    runProperty(
        "P-3 marker stability",
        fc.property(fc.noShrink(fc.gen()), (g) => {
            const gen = toGen(g)
            const name = RULES[g(fc.nat, { max: RULES.length - 1 })].name
            const { input } = FORMATS[name].gen(gen)
            const first = scan(input)
            if (first.hits.length === 0) return
            const second = scan(first.text)
            assert.equal(second.text, first.text, "re-scan must not change the redacted text")
            for (const h of second.hits) {
                assert.ok(!h.value.includes(MARKER), "no hit may contain a marker")
            }
        }),
    )
})

// ── P-4: benign pass-through corpus ───────────────────────────────────────
test("P-4: benign corpus passes through untouched", () => {
    const dir = join(import.meta.dirname, "fixtures", "benign")
    const files = readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isFile())
        .map((e) => join(dir, e.name))
    assert.ok(files.length > 0, "benign corpus must not be empty")
    for (const file of files) {
        const lines = readFileSync(file, "utf8")
            .split(/\r?\n/)
            .filter((l) => l && !l.startsWith("#"))
        for (const line of lines) {
            const r = scan(line)
            assert.equal(r.text, line, `benign fixture must pass through: ${file} :: ${line.slice(0, 40)}`)
            assert.equal(r.hits.length, 0, `benign fixture must not hit: ${file} :: ${line.slice(0, 40)}`)
        }
    }
    // Marker-bearing strings are built from MARKER at runtime (no literal).
    const markers = [
        `<${MARKER}:jwt:0123456789abcdef>`,
        `Bearer <${MARKER}:bearer-token:0123456789abcdef>`,
        `password = "<${MARKER}:secret-assignment:0123456789abcdef>"`,
        `glpat-<${MARKER}:gitlab-pat:0123456789abcdef>`,
    ]
    for (const m of markers) {
        const r = scan(m)
        assert.equal(r.text, m, "marker text must pass through")
        assert.equal(r.hits.length, 0, "marker text must not hit")
    }
})

// ── P-5: metamorphic embedding ────────────────────────────────────────────
test("P-5: boundary-preserving padding keeps detection and the fingerprint stable", () => {
    runProperty(
        "P-5 metamorphic embedding",
        fc.property(fc.noShrink(fc.gen()), (g) => {
            const gen = toGen(g)
            const name = RULES[g(fc.nat, { max: RULES.length - 1 })].name
            const { input, payload } = FORMATS[name].gen(gen)
            const plain = scan(input)
            if (plain.hits.length === 0) return
            const pad = ` context ${g(fc.nat, { max: 999 })} around `
            const embeddedText = `${pad}${input}${pad}`
            const embedded = scan(embeddedText)
            const plainHit = plain.hits.find((h) => h.rule === name)
            const embeddedHit = embedded.hits.find((h) => h.rule === name && h.value === payload)
            assert.ok(
                embeddedHit,
                `expected ${name} to fire on embedded ${JSON.stringify(embeddedText).slice(0, 90)}, got ${embedded.hits.map((h) => h.rule).join(",")}`,
            )
            assert.equal(embeddedHit.fp, plainHit?.fp, "fingerprint must be stable under padding")
        }),
    )
})

// ── P-6: validator boundaries with an independent reference entropy ───────
// Independent implementation: Map-based frequency + natural-log ratio, so the
// oracle never reuses src/rules.ts entropy() (no tautology).
function refEntropy(s: string): number {
    const freq = new Map<string, number>()
    for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1)
    let h = 0
    for (const n of freq.values()) {
        const p = n / s.length
        h -= p * (Math.log(p) / Math.LN2)
    }
    return h
}

test("P-6: src entropy agrees with the independent reference on generated strings", () => {
    runProperty(
        "P-6 entropy cross-check",
        fc.property(fc.noShrink(fc.gen()), (g) => {
            const gen = toGen(g)
            const pools = [ALNUM, HEX, " .,:;!?-_<>\"'", "éàüñß", "😀🎉", "a", "0123456789"]
            const pool = pools[g(fc.nat, { max: pools.length - 1 })]
            const s = str(gen, pool, g(fc.nat, { max: 200 }))
            assert.ok(Math.abs(entropy(s) - refEntropy(s)) < 1e-9, `entropy mismatch for ${JSON.stringify(s)}`)
        }),
    )
})

test("P-6: validator boundary classes are explicit", () => {
    // looksReal: length ≥ 8, not a placeholder, entropy ≥ 2.6
    assert.equal(looksReal("a".repeat(7)), false, "too short")
    assert.equal(looksReal("changeme"), false, "placeholder")
    assert.equal(looksReal("a".repeat(8)), false, "zero entropy")
    assert.equal(looksReal("Ab3dEf9x"), true, "8 chars, high entropy")
    // looksBare: real + not pathish/codeish + digit (or ≥ 32 chars)
    assert.equal(looksBare("/etc/ssl/certs/x.pem"), false, "path-ish")
    assert.equal(looksBare("auth.token.clone"), false, "code identifier")
    assert.equal(looksBare("AbcdefgH"), false, "no digit and < 32 chars")
    assert.equal(looksBare("Ab3dEf9xQw7"), true, "has a digit")
    // mixedBlob: lower + upper + digit + entropy ≥ 3.4
    assert.equal(mixedBlob("abcdefghijklmnopqrstuvwxyz"), false, "no upper/digit")
    assert.equal(mixedBlob("Ab3dEf9xQw7Zc2"), true, "mixed case + digit")
    // looksSecret: rejects words, versions, short identifiers
    assert.equal(looksSecret("hello world"), false, "plain words")
    assert.equal(looksSecret("v1.2.3"), false, "version string")
    assert.equal(looksSecret("abc123"), false, "short identifier")
    assert.equal(looksSecret("Ab3dEf9xQw7Zc2"), true, "high-entropy identifier")
})

// ── P-7: decode-pass budgets and ordering ─────────────────────────────────
test("P-7: at most 16 encoded candidates are redacted per decode pass", () => {
    runProperty(
        "P-7 decode cap",
        fc.property(fc.noShrink(fc.gen()), (g) => {
            const gen = toGen(g)
            const n = 20 + g(fc.nat, { max: 20 })
            const parts: string[] = []
            for (let i = 0; i < n; i++) {
                parts.push(Buffer.from(FORMATS["gitlab-pat"].gen(gen).input).toString("base64"))
            }
            const r = scan(parts.join(" "))
            const encoded = r.hits.filter((h) => h.rule === "encoded-secret")
            assert.ok(encoded.length > 0, "at least one encoded secret detected")
            assert.ok(encoded.length <= 16, `cap applied, got ${encoded.length}`)
        }),
    )
})

test("P-7: decoded values over 4096 chars stay unchanged", () => {
    const big = alnum(rngGen(makeRng(7)), 5000)
    const enc = Buffer.from(big).toString("base64")
    const r = scan(enc)
    assert.equal(r.text, enc, "over-limit decoded value must stay unchanged")
    assert.equal(r.hits.length, 0, "over-limit decoded value must not hit")
})

test("P-7: right-to-left replacement preserves sentinels", () => {
    const g = rngGen(makeRng(11))
    const secrets = Array.from({ length: 3 }, () => FORMATS["gitlab-pat"].gen(g).input)
    const encs = secrets.map((s) => Buffer.from(s).toString("base64"))
    const text = encs.join("|")
    const r = scan(text)
    const markers = r.text.split("|")
    assert.equal(markers.length, 3, "sentinels preserved")
    for (const m of markers) {
        assert.ok(m.startsWith(`<${MARKER}:encoded-secret:`), `span redacted as encoded-secret: ${m.slice(0, 40)}`)
    }
})

// ── P-8: security invariants ──────────────────────────────────────────────
test("P-8: non-string and empty inputs pass through untouched", () => {
    for (const v of [42, null, undefined, true, ["x"], { a: 1 }, ""]) {
        const r = scan(v)
        assert.equal(r.text, v, `scan(${JSON.stringify(v)}) must pass through`)
        assert.equal(r.hits.length, 0, "no hits for non-strings")
    }
})

test("P-8: the scan cache never stores hit results", () => {
    const cache = createScanCache(10)
    const secret = FORMATS["gitlab-pat"].gen(rngGen(makeRng(3))).input
    const hit = cache.scan(secret)
    assert.ok(hit.hits.length > 0, "secret must hit")
    assert.equal(cache.size, 0, "hits must never be cached")
    const clean = cache.scan("ordinary developer text")
    assert.equal(clean.hits.length, 0, "clean string stays clean")
    assert.equal(cache.size, 1, "clean strings are cached")
})

test("P-8: scanDeep is cycle-safe on shared and cyclic graphs", () => {
    const hits: Array<{ rule: string }> = []
    const cyclic: Record<string, unknown> = { label: "loop" }
    cyclic.self = cyclic
    const nested = { a: [1, 2], b: cyclic }
    const value = { nested, shared: nested }
    const out = scanDeep(value, hits)
    assert.equal(out, value, "scanDeep mutates in place")
    const outNested = out.nested as Record<string, unknown>
    assert.equal(outNested.b, cyclic, "cycle preserved, no infinite loop")
    assert.equal(value.shared, nested, "shared reference preserved")
    assert.equal(hits.length, 0, "no hits on a benign graph")
})

// ── P-9: structural preservation ──────────────────────────────────────────
test("P-9: group-rule redaction preserves delimiters and JSON parseability", () => {
    const json = `{"api_key": "Ab3dEf9xQw7Zc2KlMnOpQrStUvWxYz1234"}`
    const r = scan(json)
    assert.ok(r.text !== json, "JSON secret must be redacted")
    const obj = JSON.parse(r.text) as Record<string, string>
    assert.ok(obj.api_key.includes(MARKER), "JSON value is a marker")

    const assignment = `password = "correct horse battery staple Xy9"`
    const a = scan(assignment)
    assert.ok(a.text !== assignment, "assignment must be redacted")
    assert.ok(a.text.startsWith(`password = "`), "opening delimiter preserved")
    assert.ok(a.text.endsWith('"'), "closing delimiter preserved")

    const bearer = `Bearer Ab3dEf9xQw7Zc2KlMnOpQrStUvWxYz1234`
    const b = scan(bearer)
    assert.ok(b.text.startsWith("Bearer "), "bearer scheme preserved")
    assert.ok(b.text.includes(MARKER), "bearer value redacted")
})

// ── P-10: adversarial runtime (worker/process isolation, hard timeout) ────
function adversarialInputs(): string[] {
    const g = rngGen(makeRng(0xadbeef))
    const inputs: string[] = []
    // near-misses: valid shapes with one mutation
    inputs.push(`glpat-${sepAlnum(g, 19)}`)
    inputs.push(`glpat-${sepAlnum(g, 21)}`)
    inputs.push(`AKIA${alnumUpper(g, 15)}`)
    inputs.push(`SK${hex(g, 31)}`)
    inputs.push(`1234567890:${sepAlnum(g, 34)}`)
    inputs.push(`ghp_${alnum(g, 35)}`)
    inputs.push(`sk-proj-${sepAlnum(g, 19)}`)
    inputs.push(`hf_${alnum(g, 33)}`)
    // long delimiters around real secrets
    inputs.push(`=${"=".repeat(5000)}glpat-${sepAlnum(g, 20)}${"=".repeat(5000)}`)
    inputs.push(`"${'"'.repeat(5000)}secret_key = "${alnum(g, 40)}"${'"'.repeat(5000)}`)
    inputs.push("-".repeat(10000))
    // candidate floods: far more encoded spans than the 16-candidate cap
    const encs: string[] = []
    for (let i = 0; i < 60; i++) encs.push(Buffer.from(`glpat-${sepAlnum(g, 20)}`).toString("base64"))
    inputs.push(encs.join(" "))
    // large bounded strings
    inputs.push(Array.from({ length: 500 }, () => alnum(g, 1000)).join(" "))
    inputs.push("a".repeat(1_000_000))
    inputs.push(`password = "${"x".repeat(200_000)}"`)
    inputs.push(`Bearer ${"A".repeat(100_000)}`)
    inputs.push(`eyJ${"a".repeat(50_000)}.${"b".repeat(50_000)}.${"c".repeat(50_000)}`)
    return inputs
}

test("P-10: adversarial runtime completes under a hard timeout (worker-isolated)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sg-p10-"))
    const file = join(dir, "inputs.json")
    await writeFile(file, JSON.stringify(adversarialInputs()))
    const worker = join(import.meta.dirname, "property-p10-worker.mts")
    const child = execFile(process.execPath, ["--experimental-strip-types", worker, file], { timeout: 30_000 })
    const deadline = Date.now() + 30_000
    while (child.exitCode === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 100))
    }
    if (child.exitCode === null) {
        child.kill()
        assert.fail("worker did not exit within 30s (hard timeout; blocking regex killed)")
    }
    let stderr = ""
    for await (const chunk of child.stderr) stderr += chunk
    assert.equal(child.exitCode, 0, `worker failed: ${stderr}`)
})

// ── P-11: encoded-path coverage ───────────────────────────────────────────
const percentEncode = (s: string): string =>
    [...s].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")

test("P-11: encoded forms of generated secrets are redacted as encoded-secret", () => {
    runProperty(
        "P-11 encoded-path",
        fc.property(fc.noShrink(fc.gen()), (g) => {
            const gen = toGen(g)
            const name = RULES[g(fc.nat, { max: RULES.length - 1 })].name
            const { input } = FORMATS[name].gen(gen)
            if (input.length < 20) return // encoded-candidate floor
            const forms: Array<[string, string]> = [
                ["percent", percentEncode(input)],
                ["base64", Buffer.from(input).toString("base64")],
                ["hex", Buffer.from(input).toString("hex")],
            ]
            for (const [label, enc] of forms) {
                const r = scan(enc)
                assert.ok(r.text !== enc, `${name} ${label} form must be redacted: ${JSON.stringify(enc).slice(0, 90)}`)
                // The encoded span is redacted either by the decode pass
                // (encoded-secret) or, for long base64 forms, directly by
                // entropy-blob as plaintext (the encoded form is itself a
                // high-entropy base64 blob; same redaction outcome). Percent
                // and hex forms are never entropy-blob candidates (their
                // alphabets are not in the blob class), so they always take
                // the encoded-secret path.
                assert.ok(
                    r.hits.some((h) => h.rule === "encoded-secret" || h.rule === "entropy-blob"),
                    `${name} ${label} form must hit encoded-secret or entropy-blob, got ${r.hits.map((h) => h.rule).join(",")}`,
                )
            }
        }),
    )
    // Benign encoded text stays unchanged. The prose must be short enough that
    // its base64 stays under the 40-char entropy-blob floor (a longer base64 is
    // itself a high-entropy blob and is redacted as entropy-blob by design).
    const benign = Buffer.from("this is not a secret at all").toString("base64")
    assert.equal(scan(benign).text, benign, "benign encoded text stays unchanged")
})
