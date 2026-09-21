/**
 * rules.ts — content scanner: regex rules + Shannon entropy.
 */
import { Buffer } from "node:buffer"
import { MARKER, fp } from "./config.ts"

/** A named detection rule. `regex` must be global when it can match repeatedly. */
export type Rule = {
    name: string
    regex: RegExp
    /** 1-based. Redact only this group, preserving the surrounding syntax. */
    group?: number
    validate?: (v: string) => boolean
}

/** Shannon entropy, in bits per character. */
export function entropy(s: string): number {
    const freq: Record<string, number> = {}
    for (const c of s) freq[c] = (freq[c] ?? 0) + 1
    let h = 0
    for (const n of Object.values(freq)) {
        const probability = n / s.length
        h -= probability * Math.log2(probability)
    }
    return h
}

export const PLACEHOLDER =
    /^(?:x{3,}|\*+|\.{3,}|changeme|placeholder|example|sample|dummy|fake|test|todo|none|null|undefined|redacted|secret|password|token|your[_-]?\w*|\$\{[^}]*\}|<[^>]*>|\$[A-Z_]+|env!.*)$/i

/** Entropy floors (bits per character) used by the validators below. */
const ENTROPY_REAL_MIN = 2.6
const ENTROPY_SECRET_MIN = 3.2
const ENTROPY_MIXED_MIN = 3.4
const ENTROPY_BLOB_MIN = 4.2

/** Generic "looks like a real secret": long enough, not a placeholder, ≥2.6 bits/char. */
export const looksReal = (v: string): boolean => v.length >= 8 && !PLACEHOLDER.test(v) && entropy(v) >= ENTROPY_REAL_MIN

/** base64-like blob: mixed case, digits and ≥3.4 bits/char. */
export const mixedBlob = (v: string): boolean =>
    /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v) && entropy(v) >= ENTROPY_MIXED_MIN

// ── Anti over-redaction for obfstr! ──────────────────────────────────────
// obfstr! is often used as anti-tamper on EVERY string, not only on secrets.
// Without these filters, ordinary words, version strings and short identifiers
// that merely look random would be redacted.
export const WORDISH = /^[A-Za-z][a-z]*(?:[ _-][A-Za-z][a-z]*)*$/ // plain words
export const VERSIONISH = /^v?\d+(?:\.\d+){1,3}$/i // version strings
export const SHORTISH = /^[A-Za-z0-9._-]{1,11}$/ // short identifiers

/**
 * `obfstr!` literal gate: rejects plain words, version strings and short
 * identifiers so ordinary code strings are not redacted.
 */
export const looksSecret = (v: string): boolean =>
    !WORDISH.test(v) && !VERSIONISH.test(v) && !SHORTISH.test(v) && (entropy(v) >= ENTROPY_SECRET_MIN || v.length >= 24)

// ── Anti over-redaction for unquoted values ──────────────────────────────
/** /etc/ssl/certs/x.pem, ./cfg/keys.json — paths, not secrets. */
export const PATHISH = /^(?:[~.]?\/|[A-Za-z]:\\|\/(?:[\w.-]+\/)+[\w.-]*$)/i
/** temp_token.clone, self.token, obj::method — code identifiers. */
export const CODEISH = /^[A-Za-z_$][\w$]*(?:[.\-:]+[A-Za-z_$][\w$]*)+$/

/**
 * Unquoted credential gate: a real credential almost always contains a digit or
 * is long; paths and code identifiers are excluded to avoid over-redaction.
 */
export const looksBare = (v: string): boolean =>
    looksReal(v) && !PATHISH.test(v) && !CODEISH.test(v) && (/\d/.test(v) || v.length >= 32) // a real credential almost always has digits

export const RULES: Rule[] = [
    // obfstr!("...") -> keep the literal valid Rust
    {
        name: "obfuscated-string",
        regex: /\b(?:obfstr|obfstring|obfuscate|xor_str|encrypt_str|hide_str)\s*!?\s*[({[]\s*(?:r#*)?["']([^"'\n]{4,512})["']/gi,
        group: 1,
        validate: looksSecret,
    },

    // ── specific formats (also catch comments) ──
    { name: "license-token", regex: /\b[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}\b/g },
    { name: "hw-fingerprint", regex: /\b[0-9A-F]{4}(?:-[0-9A-F]{4}){5,9}\b/g },

    { name: "aws-access-key", regex: /\bAKIA[0-9A-Z]{16}\b/g },
    {
        name: "aws-secret-key",
        regex: /(?:aws)?_?secret_?(?:access)?_?key\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi,
        group: 1,
    },
    { name: "github-token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
    { name: "slack-token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
    { name: "stripe-key", regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
    { name: "google-api-key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },

    // ── curated provider tokens (high-signal prefixes) ──
    { name: "gitlab-pat", regex: /\bglpat-[A-Za-z0-9_-]{20}\b/g },
    { name: "npm-token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { name: "pypi-token", regex: /\bpypi-[A-Za-z0-9_-]{34,}\b/g },
    { name: "twilio-key", regex: /\bSK[0-9a-fA-F]{32}\b/g },
    { name: "sendgrid-key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
    { name: "mailgun-key", regex: /\bkey-[0-9a-f]{32}\b/g },
    { name: "discord-bot-token", regex: /\b[MNO][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,38}\b/g },
    { name: "digitalocean-token", regex: /\bdop_v1_[0-9a-f]{64}\b/g },
    { name: "shopify-token", regex: /\bshpat_[0-9a-fA-F]{32}\b/g },
    { name: "telegram-bot-token", regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g },
    { name: "anthropic-key", regex: /\bsk-ant-[A-Za-z0-9_-]{24,}\b/g },
    { name: "openai-key", regex: /\bsk-(?:proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})\b/g },
    { name: "huggingface-token", regex: /\bhf_[A-Za-z0-9]{34}\b/g },
    { name: "google-oauth-token", regex: /\bya29\.[A-Za-z0-9_-]{24,}\b/g },
    { name: "azure-storage-key", regex: /AccountKey=([A-Za-z0-9+/]{86}==)/g, group: 1 },
    {
        // Context-sensitive: a bare UUID is not a secret (ids, hashes, refs).
        name: "heroku-api-key",
        regex: /\bheroku\b[^\n]{0,20}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi,
        group: 1,
    },
    {
        // Redundant with private-key-block for parsed objects; clearer in raw JSON.
        name: "gcp-service-account",
        regex: /"private_key"\s*:\s*"([^"]*-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?)"/g,
        group: 1,
        validate: (v) => v.length >= 100,
    },

    // ── adversarial corpus: FUZZ.md gaps (add-adversarial-corpus, batch 2) ──
    // Distinctive prefixes, conservative lengths; placed before the generic
    // catch-alls so each fires with its own name (design D2).
    { name: "aws-sts-key", regex: /\bASIA[0-9A-Z]{16}\b/g },
    { name: "github-fine-grained-pat", regex: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g },
    {
        name: "slack-app-token",
        regex: /\bxapp-[A-Za-z0-9-]{10,}\b/g,
        // Real app-level tokens are xapp-<n>-…; the digit keeps ordinary
        // hyphenated words (e.g. "xapp-navigation") out (found by P-4).
        validate: (v) => /\d/.test(v),
    },
    { name: "stripe-restricted-key", regex: /\brk_live_[0-9a-zA-Z]{24,}\b/g },

    // ── adversarial corpus: LLM providers (add-adversarial-corpus, batch 3) ──
    { name: "groq-key", regex: /\bgsk_[A-Za-z0-9]{48}\b/g },
    { name: "xai-key", regex: /\bxai-[A-Za-z0-9]{80}\b/g },
    { name: "replicate-token", regex: /\br8_[A-Za-z0-9]{37}\b/g },
    { name: "perplexity-key", regex: /\bpplx-[A-Za-z0-9]{30,}\b/g },

    // ── adversarial corpus: infra/cloud (add-adversarial-corpus, batch 4) ──
    { name: "grafana-service-account-token", regex: /\bglsa_[A-Za-z0-9_]{32,}\b/g },
    { name: "docker-pat", regex: /\bdckr_pat_[A-Za-z0-9_-]{26,}\b/g },
    { name: "vault-token", regex: /\bhvs\.[A-Za-z0-9]{24,}\b/g },
    {
        name: "tailscale-key",
        regex: /\btskey-[A-Za-z0-9-]{10,}\b/g,
        // Real keys are tskey-auth-… / tskey-api-…; the digit keeps ordinary
        // hyphenated words (e.g. "tskey-navigation") out (found by P-4).
        validate: (v) => /\d/.test(v),
    },

    // ── adversarial corpus: remaining providers (add-adversarial-corpus, batch 5) ──
    { name: "pulumi-token", regex: /\bpul-[A-Za-z0-9]{40}\b/g },
    { name: "render-key", regex: /\brnd_[A-Za-z0-9]{40,}\b/g },
    {
        name: "doppler-token",
        regex: /\bdp\.(?:st\.(?:[a-z0-9_-]{2,35}\.)?|pt\.|ct\.|said\.|sa\.)[A-Za-z0-9]{40,44}\b/g,
    },
    { name: "resend-key", regex: /\bre_[A-Za-z0-9_]{30,}\b/g },
    { name: "brevo-key", regex: /\bxkeysib-[A-Za-z0-9]{40,}\b/g },
    { name: "linear-key", regex: /\blin_api_[A-Za-z0-9]{30,}\b/g },

    {
        name: "private-key-block",
        // No 8192 ceiling, and support for the real PGP "PRIVATE KEY BLOCK" header.
        regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    },
    { name: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
    {
        name: "db-connection-string",
        regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/]+:([^@\s]+)@/gi,
        group: 1,
    },
    { name: "bearer-token", regex: /\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)/g, group: 1 },
    {
        name: "bare-credential",
        // HTTP headers, CLI flags, .ini/.conf/.properties — where the quotes
        // wrap the "Key: value" pair rather than the value itself.
        regex: /\b(?:x-)?(?:api[-_]?keys?|apikey|auth(?:orization)?|access[-_]?(?:key|token)|token|secret|client[-_]?secret|private[-_]?key|password|passwd|pwd)\w*\s*[:=]\s*(?:Bearer\s+|Basic\s+|Token\s+)?([A-Za-z0-9\-._~+/]{16,}={0,2})/gi,
        group: 1,
        validate: looksBare,
    },
    {
        name: "credential-field",
        // JSON/YAML-style credential fields may have a product prefix
        // (e.g. QDRANT_API_KEY) and provider-specific token formats.
        regex: /"[^"\n]*(?:api[-_]?keys?|authorization|access[-_]?(?:key|token)|token|secret|client[-_]?secret|private[-_]?key|password|passwd|pwd)[^"\n]*"\s*:\s*"(?:Bearer\s+|Basic\s+|Token\s+)?([^"\n]{6,512})"/gi,
        group: 1,
        validate: (v) => !PLACEHOLDER.test(v),
    },
    {
        name: "entropy-blob",
        // A blob isolated on a line: openssl rand / uuidgen / key-generator output.
        // No "/" in the class/boundaries: a secret after a slash (URL/path) must
        // still be caught. Trade-off: base64 containing "/" is split into segments.
        regex: /(?<![\w+=-])([A-Za-z0-9+=_-]{40,512})(?![\w+=-])/g,
        group: 1,
        validate: (v) =>
            !CODEISH.test(v) &&
            !PATHISH.test(v) &&
            /[a-z]/.test(v) &&
            /[A-Z]/.test(v) &&
            /\d/.test(v) &&
            entropy(v) >= ENTROPY_BLOB_MIN,
    },
    {
        name: "secret-assignment",
        regex: /\b(?:secret|password|passwd|pwd|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|auth)\w*\s*(?::\s*&?\w+\s*)?[:=]\s*(?:[\w:.]+\s*!?\s*[({[]\s*)?["']([^"'\n]{6,512})["']/gi,
        group: 1,
        validate: looksReal,
    },
    {
        name: "base64-blob",
        regex: /["']([A-Za-z0-9+/]{32,}={0,2})["']/g,
        group: 1,
        validate: mixedBlob,
    },
]

/** Cheap pre-filter: avoids running every regex over innocuous output. */
export const INDICATOR =
    /obfstr|obfuscate|xor_str|encrypt_str|hide_str|secret|token|passw|pwd|api[_-]?key|apikey|authoriz|private[_-]?key|access[_-]?key|client[_-]?secret|credential|AKIA|ASIA[0-9A-Z]{16}|gh[pousr]_|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-|xapp-[A-Za-z0-9-]{10,}|sk_live_|rk_live_[0-9a-zA-Z]{24,}|gsk_[A-Za-z0-9]{48}|xai-[A-Za-z0-9]{80}|r8_[A-Za-z0-9]{37}|pplx-[A-Za-z0-9]{30,}|glsa_[A-Za-z0-9_]{32,}|dckr_pat_[A-Za-z0-9_-]{26,}|hvs\.[A-Za-z0-9]{24,}|tskey-[A-Za-z0-9-]{10,}|pul-[A-Za-z0-9]{40}|rnd_[A-Za-z0-9]{40,}|dp\.(?:st\.(?:[a-z0-9_-]{2,35}\.)?|pt\.|ct\.|said\.|sa\.)[A-Za-z0-9]{40,44}|re_[A-Za-z0-9_]{30,}|xkeysib-[A-Za-z0-9]{40,}|lin_api_[A-Za-z0-9]{30,}|AIza|glpat-|npm_[A-Za-z0-9]|pypi-|SG\.|dop_v1_|shpat_|sk-ant-|sk-proj-|sk-[A-Za-z0-9]{32}|hf_[A-Za-z0-9]|ya29\.|AccountKey=|heroku|private_key|[MNO][A-Za-z\d]{23}\.|discord|SK[0-9a-f]{32}|key-[0-9a-f]{32}|BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{8}|Bearer\s|[A-Za-z0-9+/]{32,}={0,2}|:\/\/[^\s@/]+:[^\s@/]+@|\b[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}\b|\b[0-9A-F]{4}(?:-[0-9A-F]{4}){5}|\d{8,10}:[A-Za-z0-9_-]{35}|[A-Za-z0-9+=_-]{40,512}/i

/** One redaction: the rule that fired, the value's fingerprint, and the value. */
export type Hit = { rule: string; fp: string; value: string }
/** Result of a scan: the redacted text plus every hit. */
export type Scan = { text: string; hits: Hit[] }

// ── built-in allowlist: known documentation/example values ───────────────
const ALLOWLIST = new Set<string>(["AKIA" + "IOSFODNN7EXAMPLE"])
// Whole-value placeholders only (PLACEHOLDER is anchored): a real secret that
// merely *contains* "sample"/"example" as a substring must still be redacted.
const isAllowlisted = (v: string): boolean => ALLOWLIST.has(v) || PLACEHOLDER.test(v)

// ── encoded-secret detection ─────────────────────────────────────────────
// Runs independently of INDICATOR: percent runs and short base64 are not
// matched by the plaintext pre-filter (verified), so a decode gated only by
// INDICATOR would never run for them.
const ENCODED = /(?:%[0-9A-Fa-f]{2}){3,}|[A-Za-z0-9+/_-]{20,}={0,2}/
const PERCENT_RE = /(?:%[0-9A-Fa-f]{2}){3,}/g
const CANDIDATE_RE = /[A-Za-z0-9+/_-]{20,}={0,2}/g
const MIN_CANDIDATE = 20
const DECODED_MAX = 4096
const MAX_CANDIDATES = 16

const percentDecode = (s: string): string => {
    try {
        return decodeURIComponent(s)
    } catch {
        return ""
    }
}
const base64Decode = (s: string): string => {
    try {
        return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("latin1")
    } catch {
        return ""
    }
}
const hexDecode = (s: string): string => {
    if (s.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/.test(s)) return ""
    try {
        return Buffer.from(s, "hex").toString("latin1")
    } catch {
        return ""
    }
}
// The candidate gate is the length floor only. Entropy/digit/letter heuristics
// were dropped: they are undocumented and rejected encoded forms of detected
// secrets (e.g. a license token whose base64 happens to lack digits), a false
// negative. The real gate is the decode + rule check in `redactEncoded`, and
// the 16-candidate cap bounds the decode cost.
const looksEncoded = (s: string): boolean => s.length >= MIN_CANDIDATE

/** Escapes a literal for embedding in a RegExp (kept local: module order). */
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

/**
 * Already-redacted spans. Rules never run inside them: a marker hash can look
 * like a credential to a keyword rule (e.g. `bearer-token:<hex>` matches
 * `bare-credential`), which would re-redact and nest markers on every rescan.
 */
const MARKER_SPAN = new RegExp(`<${escapeRe(MARKER)}:[^:>]+:[0-9a-f]{16}>`, "g")

/** Applies only the plaintext RULES to a marker-free segment. */
function applyRulesSegment(segment: string, hits: Hit[]): string {
    let text = segment

    for (const rule of RULES) {
        text = text.replace(rule.regex, (match: string, ...rest: unknown[]) => {
            // rest = [...groups, offset, fullString] (+ groupsObj for named groups)
            const tail = typeof rest[rest.length - 1] === "object" ? 3 : 2
            const groups = rest.slice(0, -tail) as (string | undefined)[]

            const payload = rule.group ? groups[rule.group - 1] : match
            if (!payload) return match
            if (payload.includes(MARKER)) return match // idempotency
            if (isAllowlisted(payload)) return match
            if (rule.validate && !rule.validate(payload)) return match

            const digest = fp(payload)
            hits.push({ rule: rule.name, fp: digest, value: payload })
            const token = `<${MARKER}:${rule.name}:${digest}>`

            if (rule.group) {
                // preserve syntax: obfstr!("<...>") still compiles
                const i = match.lastIndexOf(payload)
                return match.slice(0, i) + token + match.slice(i + payload.length)
            }
            return token
        })
    }

    return text
}

/** Applies the plaintext RULES outside every existing marker span. */
function applyRules(input: string): Scan {
    const hits: Hit[] = []
    let out = ""
    let last = 0
    MARKER_SPAN.lastIndex = 0
    let match = MARKER_SPAN.exec(input)
    while (match !== null) {
        out += applyRulesSegment(input.slice(last, match.index), hits) + match[0]
        last = match.index + match[0].length
        match = MARKER_SPAN.exec(input)
    }
    return { text: out + applyRulesSegment(input.slice(last), hits), hits }
}

/** Redacts an encoded span when its decoding matches a rule. Vault gets the span. */
function redactEncoded(encoded: string, decode: (s: string) => string, hits: Hit[]): string {
    const decoded = decode(encoded)
    if (!decoded || decoded.length > DECODED_MAX) return encoded
    if (applyRules(decoded).hits.length === 0) return encoded
    const digest = fp(encoded)
    hits.push({ rule: "encoded-secret", fp: digest, value: encoded })
    return `<${MARKER}:encoded-secret:${digest}>`
}

function decodePass(text: string, hits: Hit[]): string {
    type Candidate = { value: string; index: number; percent: boolean }
    const seen = new Set<number>()
    const candidates: Candidate[] = []

    const collect = (re: RegExp, percent: boolean): void => {
        re.lastIndex = 0
        let match: RegExpExecArray | null
        // biome-ignore lint/suspicious/noAssignInExpressions: canonical regex exec loop
        while ((match = re.exec(text)) !== null) {
            if (!seen.has(match.index) && looksEncoded(match[0])) {
                seen.add(match.index)
                candidates.push({ value: match[0], index: match.index, percent })
            }
            if (match.index === re.lastIndex) re.lastIndex++
        }
    }
    collect(PERCENT_RE, true)
    collect(CANDIDATE_RE, false)

    // Highest entropy first: real secrets rank above ordinary identifiers, so
    // the per-scan cap drops the least secret-looking candidates.
    candidates.sort((a, b) => entropy(b.value) - entropy(a.value))
    const chosen = candidates.slice(0, MAX_CANDIDATES)
    chosen.sort((a, b) => b.index - a.index) // apply right-to-left: indices stay valid

    let out = text
    for (const c of chosen) {
        let replacement = c.value
        if (c.percent) {
            replacement = redactEncoded(c.value, percentDecode, hits)
        } else {
            for (const decode of [base64Decode, hexDecode]) {
                const encoded = redactEncoded(c.value, decode, hits)
                if (encoded !== c.value) {
                    replacement = encoded
                    break
                }
            }
        }
        if (replacement !== c.value) {
            out = out.slice(0, c.index) + replacement + out.slice(c.index + c.value.length)
        }
    }
    return out
}

/**
 * Scans a string and returns the redacted text plus the hits. Non-strings and
 * empty strings pass through untouched; cheap pre-filters gate the work.
 */
export function scan(input: unknown): Scan {
    if (typeof input !== "string" || !input) return { text: input as string, hits: [] }
    const hasIndicator = INDICATOR.test(input)
    const hasEncoded = ENCODED.test(input)
    if (!hasIndicator && !hasEncoded) return { text: input, hits: [] }

    const hits: Hit[] = []
    let text = input
    if (hasIndicator) {
        const applied = applyRules(input)
        text = applied.text
        hits.push(...applied.hits)
    }
    if (hasEncoded) text = decodePass(text, hits)
    return { text, hits }
}

/**
 * Applies `scan` to every string of a value, in place, guarding against cycles.
 * Unlike the helpers in `redact.ts` this does not fail closed per string: it is
 * used for tool metadata where a scanner error is caught by the caller.
 */
export function scanDeep(value: unknown, hits: Hit[], seen = new WeakSet<object>()): unknown {
    if (typeof value === "string") {
        const result = scan(value)
        hits.push(...result.hits)
        return result.text
    }
    if (value == null || typeof value !== "object") return value
    if (seen.has(value)) return value
    seen.add(value)
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) value[i] = scanDeep(value[i], hits, seen)
        return value
    }
    const record = value as Record<string, unknown>
    for (const k of Object.keys(record)) record[k] = scanDeep(record[k], hits, seen)
    return value
}

export const rulesOf = (hits: Hit[]): string[] => [...new Set(hits.map((h) => h.rule))]
export const uniqueOf = (hits: Hit[]): number => new Set(hits.map((h) => h.fp)).size

/** Default bound for the negative scan cache (see `createScanCache`). */
export const SCAN_CACHE_MAX = 1000

export interface ScanCache {
    /** Memoized scanner: negative results are cached, positives are re-scanned. */
    scan(text: string): Scan
    /** Drop every entry. */
    clear(): void
    /** Number of cached (clean) strings. */
    readonly size: number
}

/**
 * Bounded LRU cache of negative scan results. Only strings that produced no
 * hits are cached, so the cache never retains a secret value; the keys are the
 * clean strings themselves. `max <= 0` disables caching. The underlying
 * scanner is injectable (defaults to `scan`) so tests can count invocations.
 */
export function createScanCache(max: number, scanFn: (text: string) => Scan = scan): ScanCache {
    // Map preserves insertion order; delete+set implements LRU.
    const clean = new Map<string, true>()

    function memoScan(text: string): Scan {
        if (max <= 0) return scanFn(text)
        if (clean.has(text)) {
            clean.delete(text)
            clean.set(text, true)
            return { text, hits: [] }
        }
        const result = scanFn(text)
        if (result.hits.length === 0) {
            clean.set(text, true)
            while (clean.size > max) {
                const oldest = clean.keys().next().value
                if (oldest === undefined) break
                clean.delete(oldest)
            }
        }
        return result
    }

    function clear(): void {
        clean.clear()
    }

    return {
        scan: memoScan,
        clear,
        get size() {
            return clean.size
        },
    }
}
