// Adversarial corpus harness (add-adversarial-corpus).
//
// Reads tests/security-guard/fixtures/adversarial/ and asserts both sides:
// must-catch rows are redacted with the expected rule and vault payload;
// must-not-catch rows pass through untouched. Run with the rest of the suite:
//   npm test
import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { loadGuard } from "./extract.mts"

const g: Record<string, any> = await loadGuard()
const { scan } = g
const DIR = join(import.meta.dirname, "fixtures", "adversarial")

type DataRow = { text: string; line: number }

type FixtureFactory = () => string

// Keep provider-shaped values out of committed fixtures. GitHub Push Protection
// blocks pushes containing credential patterns, even synthetic test data. Runtime
// construction preserves coverage and avoids normalizing key-shaped data in source.
const FIXTURES: Record<string, FixtureFactory> = {
    "gitlab-pat": () => `glpat-${"A1b2C3d4".repeat(3).slice(0, 20)}`,
    "aws-sts-key": () => `ASIA${"A1B2C3D4".repeat(2)}`,
    "github-fine-grained-pat": () => `github_pat_${"A1b2C3d4".repeat(5)}`,
    "slack-app-token": () => `xapp-1-${"A1b2C3d4".repeat(2)}`,
    "stripe-restricted-key": () => `rk_live_${"0123456789abcdef".repeat(2).slice(0, 24)}`,
    "groq-key": () => `gsk_${"A1b2C3d4".repeat(6)}`,
    "xai-key": () => `xai-${"A1b2C3d4".repeat(10)}`,
    "replicate-token": () => `r8_${"A1b2C3d4".repeat(5).slice(0, 37)}`,
    "perplexity-key": () => `pplx-${"A1b2C3d4".repeat(4)}`,
    "grafana-service-account-token": () => `glsa_${"A1b2C3d4".repeat(4)}`,
    "docker-pat": () => `dckr_pat_${"A1b2C3d4".repeat(4)}`,
    "vault-token": () => `hvs.${"a1B2c3D4".repeat(3)}`,
    "tailscale-key": () => `tskey-auth-${"A1b2C3d4".repeat(2)}`,
    "pulumi-token": () => `pul-${"A1b2C3d4".repeat(5)}`,
    "render-key": () => `rnd_${"A1b2C3d4".repeat(5)}`,
    "doppler-token": () => `dp.st.fixture.${"a1B2c3D4".repeat(5)}`,
    "doppler-short": () => `dp.st.${"a1B2c3D4".repeat(5).slice(0, 39)}`,
    "doppler-overlong": () => `dp.st.${"a1B2c3D4".repeat(6).slice(0, 45)}`,
    "resend-key": () => `re_${"A1b2C3d4".repeat(4)}`,
    "brevo-key": () => `xkeysib-${"A1b2C3d4".repeat(5)}`,
    "linear-key": () => `lin_api_${"A1b2C3d4".repeat(4)}`,
    "shopify-overlong": () => `shpat_${"0123456789abcdef".repeat(2)}0`,
}

function resolveFixture(value: string, line: number): string {
    const match = /^<fixture:([a-z0-9-]+)>$/.exec(value)
    if (!match) return value

    const name = match[1]
    const factory = name ? FIXTURES[name] : undefined
    if (!factory) throw new Error(`unknown fixture "${name ?? ""}" at line ${line}`)
    return factory()
}

/** Non-empty, non-comment lines with their 1-based line numbers. */
function dataRows(name: string): DataRow[] {
    const raw = readFileSync(join(DIR, name), "utf8")
    const rows: DataRow[] = []
    raw.split(/\r?\n/).forEach((text, i) => {
        const trimmed = text.trim()
        if (trimmed === "" || trimmed.startsWith("#")) return
        rows.push({ text, line: i + 1 })
    })
    return rows
}

type CatchRow = { rule: string; value: string; line: number }

/** Parses `<rule-name><TAB><value>` must-catch rows. */
function catchRows(): CatchRow[] {
    return dataRows("must-catch.txt").map(({ text, line }) => {
        const tab = text.indexOf("\t")
        assert.ok(tab > 0, `must-catch.txt:${line} must be "<rule-name><TAB><value>"`)
        const rule = text.slice(0, tab).trim()
        const value = resolveFixture(text.slice(tab + 1).trim(), line)
        assert.ok(rule !== "" && value !== "", `must-catch.txt:${line} has an empty field`)
        return { rule, value, line }
    })
}

test("adversarial must-catch rows are redacted with the expected rule and payload", () => {
    const rows = catchRows()
    assert.ok(rows.length > 0, "must-catch corpus must not be empty")
    for (const row of rows) {
        const result = scan(row.value)
        assert.notEqual(result.text, row.value, `must-catch.txt:${row.line} must be redacted`)
        const hit = result.hits.find((h: any) => h.rule === row.rule)
        const seen = result.hits.map((h: any) => h.rule)
        assert.ok(hit, `must-catch.txt:${row.line} expected "${row.rule}", got [${seen.join(",")}]`)
        assert.equal(hit.value, row.value, `must-catch.txt:${row.line} "${row.rule}" payload must be the value`)
    }
})

test("adversarial must-not-catch rows pass through untouched", () => {
    for (const { text, line } of dataRows("must-not-catch.txt")) {
        const value = resolveFixture(text, line)
        const result = scan(value)
        assert.equal(result.text, value, `must-not-catch.txt:${line} must be unchanged`)
        assert.equal(result.hits.length, 0, `must-not-catch.txt:${line} must not hit`)
    }
})
