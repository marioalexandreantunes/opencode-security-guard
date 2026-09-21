// security-guard regression suite (scanner + shell unit diagnostics).
// Bash hook behaviour is covered by before-hook.test.mts against the real hook.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/regression.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { loadGuard, loadFactory } from "./extract.mts"
import { scan } from "../../src/rules.ts"

const g: Record<string, any> = await loadGuard()
const { scanDeep, sensitiveToken, isSensitivePath, ENV_DUMP, PS_ENV, ENV_ECHO, ENV_EXPORT, WRITE_VERB, MARKER } = g

const redacted = (s: string): boolean => scan(s).text !== s
const mk = (rule: string, hash = "0123456789abcdef"): string => `<${MARKER}:${rule}:${hash}>`

// Reviewed deterministic positive fixtures (make-test-suite-reproducible).
// Unseeded random bytes no longer decide whether a case satisfies its scanner
// precondition. Each value is synthetic, non-production and chosen against the
// complete input passed to `scan()` so it exercises the named detector: see
// the change's evidence.md for the probe and route measurements.
const BEARER_FIXTURE = "SynthBearerTokenA1b2C3d4E5f6" // 28 chars → bearer-token
const BASE64_BLOB_FIXTURE = "BlobFixtureA1b2C3d4E5f6G7h8I9j0K1l2" // 35 chars → base64-blob (under the 40-char entropy-blob floor)
const OBFUSCATED_FIXTURE = "SynthObfuscatedA1b2C3d4E5f6" // 27 chars → obfuscated-string
const URL_SECRET_FIXTURE = "UrlFixtureA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9" // 48 chars → entropy-blob
// Build this fixture at runtime. GitHub Push Protection blocks provider-shaped
// values in commits, even when they are synthetic test data.
const GOOGLE_API_KEY_FIXTURE = ["AIza", "SynthGoogle", "ApiKeyA1b2", "C3d4E5f6", "G7h8I0"].join("") // 35-char body -> google-api-key

// ─────────────────────────────────────────────────────────────────────────────
test("rules: real formats are redacted by their named detector", () => {
    const cases: Array<[string, string]> = [
        ["license-token", "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY"],
        ["hw-fingerprint", "A1B2-C3D4-E5F6-7890-ABCD-EF01"],
        ["aws-access-key", "AKIA" + "A1B2C3D4E5F6G7H8"],
        ["github-token", "ghp_" + "oNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzA"],
        ["slack-token", "xoxb-" + "1234567890-" + "abcdefghijklmnop"],
        ["stripe-key", "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz"],
        ["google-api-key", GOOGLE_API_KEY_FIXTURE],
        ["jwt", "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxIn0" + "." + "c2lnbmF0dXJlMTIzNDU2Nzg5MA"],
        ["private-key-block", `-----BEGIN RSA PRIVATE KEY-----\n${"A".repeat(400)}\n-----END RSA PRIVATE KEY-----`],
        ["db-connection-string", "postgres://alice:P4ss!wordX9@db.internal:5432/app"],
        ["bearer-token", `Authorization: Bearer ${BEARER_FIXTURE}`],
        ["bare-credential", "api_key=" + "Xy9kQ2mN7vR4tW8zB5c"],
        ["secret-assignment", 'password = "S3cr3tP4ssw0rd!2026"'],
        ["base64-blob", `"${BASE64_BLOB_FIXTURE}"`],
        ["entropy-blob", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh"],
        ["obfuscated-string", `obfstr!("${OBFUSCATED_FIXTURE}")`],
    ]
    for (const [name, value] of cases) {
        const result = scan(value)
        assert.ok(result.text !== value, `should redact ${name}: ${value.slice(0, 24)}…`)
        // The case name claims a detector: prove that detector fired instead of
        // relying on a broader rule that happened to redact the same input.
        const rules = [...new Set(result.hits.map((h) => h.rule))]
        assert.ok(
            result.hits.some((h) => h.rule === name),
            `${name} must be redacted by its named detector, got: ${rules.join(", ") || "none"}`,
        )
    }
})

test("anti-over-redaction: legitimate values are untouched", () => {
    const keep = [
        "Free",
        "Donator",
        "Developer",
        "1.0.0.11",
        "V3",
        "ICECUBE",
        "COC",
        "/etc/ssl/certs/x.pem",
        "./cfg/keys.json",
        "temp_token.clone",
        "self.token",
        "obj::method",
        "easy",
        "password",
        "token",
        "test",
        "placeholder",
        "example.com",
    ]
    for (const v of keep) assert.ok(!redacted(v), `should not redact: ${v}`)
})

test("idempotency: markers are not re-redacted", () => {
    // `bearer-token:<hash>` / `secret-assignment:<hash>` would otherwise match
    // the keyword-based `bare-credential` rule on rescan and nest markers.
    for (const rule of ["secret-assignment", "bearer-token", "npm-token", "entropy-blob"]) {
        const once = scan(mk(rule))
        const twice = scan(once.text)
        assert.equal(twice.text, once.text, `${rule} marker must be stable across rescans`)
    }
})

test("secrets in URL/path with / are detected", () => {
    // Validate the complete input span, not only the isolated value: the
    // entropy-blob class includes "=", so a query is matched as the whole
    // `key=<value>` assignment rather than the value alone.
    const path = scan(`https://host/v1/${URL_SECRET_FIXTURE}`)
    assert.equal(
        path.hits.find((h) => h.rule === "entropy-blob")?.value,
        URL_SECRET_FIXTURE,
        "URL path: the secret span is the isolated value",
    )
    const query = scan(`https://host/api?key=${URL_SECRET_FIXTURE}`)
    assert.equal(
        query.hits.find((h) => h.rule === "entropy-blob")?.value,
        `key=${URL_SECRET_FIXTURE}`,
        "URL query: the secret span includes the key= assignment",
    )
    const afterSlash = scan(`x/${URL_SECRET_FIXTURE}`)
    assert.equal(
        afterSlash.hits.find((h) => h.rule === "entropy-blob")?.value,
        URL_SECRET_FIXTURE,
        "after slash: the secret span is the isolated value",
    )
})

test("legitimate paths do not trigger scanner false positives", () => {
    for (const p of [
        "/etc/ssl/certs/x.pem",
        "/usr/local/share/doc/pkg-1.2.3/README",
        "https://github.com/user/repo/blob/main/file.ts",
    ]) {
        assert.ok(!redacted(p), `false positive: ${p}`)
    }
})

test("private-key-block: block > 8192 chars is redacted", () => {
    const big = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n${"A".repeat(9000)}\n-----END PGP PRIVATE KEY BLOCK-----`
    assert.ok(redacted(big), "9000-char PEM")
})

test("scanDeep: secret at depth 15 is detected", () => {
    const root: any = {}
    let cur = root
    for (let i = 0; i < 15; i++) {
        cur.next = {}
        cur = cur.next
    }
    cur.leaf = "api_key=" + "Xy9kQ2mN7vR4tW8zB5c"
    const hits: any[] = []
    scanDeep(root, hits)
    assert.ok(hits.length > 0, "did not descend to the leaf")
})

// ─────────────────────────────────────────────────────────────────────────────
test("sensitiveToken: false positives stay clear", () => {
    const shouldPass = [
        "ls -la .env",
        "rm .env",
        "git diff .env",
        "sort .env",
        "diff .env .env.example",
        'git commit -m "fix .env"',
        "grep credentials src/",
        'grep "BEGIN" key.pem',
        "copy C:\\proj\\notes.txt D:\\x",
    ]
    for (const c of shouldPass) assert.equal(sensitiveToken(c), null, `should not block: ${c}`)
})

test("WRITE_VERB: case matrix", () => {
    const yes = [
        "echo x 1> /tmp/f",
        "echo x 2>> /tmp/f",
        "echo x > /tmp/f",
        "echo x >> /tmp/f",
        "Set-Content x",
        "Add-Content x",
        "Out-File x",
        "New-Item x",
        "Copy-Item a b",
        "Move-Item a b",
        "Rename-Item a b",
        "tee x",
        "dd if=/dev/zero",
        "install -m 644 a b",
        "sed -i s/x/y/ f",
    ]
    const no = ["a -> b", "a => b", "a >= b", "cmd 2>&1", "cmd >&2", "sed -e s/x/y/ f", "echo hi"]
    for (const c of yes) assert.ok(WRITE_VERB.test(c), `should detect write: ${c}`)
    for (const c of no) assert.ok(!WRITE_VERB.test(c), `write false positive: ${c}`)
})

test("env: expanded rules", () => {
    const yes = [
        "env -0",
        "printenv API_TOKEN",
        "printenv",
        "env",
        "export -p",
        "gci env: | grep PASS",
        "Get-ChildItem Env:API_TOKEN",
        "Write-Output $env:API_TOKEN",
        "echo $env:PATH",
    ]
    const no = ["env FOO=bar node x", "set -e", "ls"]
    for (const c of yes)
        assert.ok(
            ENV_DUMP.test(c) || PS_ENV.test(c) || ENV_ECHO.test(c) || ENV_EXPORT.test(c),
            `should detect env: ${c}`,
        )
    for (const c of no)
        assert.ok(
            !(ENV_DUMP.test(c) || PS_ENV.test(c) || ENV_ECHO.test(c) || ENV_EXPORT.test(c)),
            `env false positive: ${c}`,
        )
})

test("isSensitivePath: .envrc and Windows", () => {
    assert.ok(isSensitivePath(".envrc"), ".envrc")
    assert.ok(isSensitivePath("nested/.envrc"), "nested/.envrc")
    assert.ok(isSensitivePath("C:\\Users\\m\\.env"), "Windows .env")
    assert.ok(!isSensitivePath("x.env"), "x.env is not .env")
    assert.ok(isSensitivePath("C:\\Users\\me\\.ssh\\id_rsa"), "drive .ssh")
    assert.ok(isSensitivePath("D:/work/.aws/credentials"), "forward slashes .aws")
    assert.ok(isSensitivePath("\\\\server\\share\\.env"), "UNC .env")
    assert.ok(isSensitivePath("C:\\proj\\.ENV"), "case-insensitive .ENV")
    assert.ok(isSensitivePath("C:\\Users\\me\\ID_RSA"), "case-insensitive ID_RSA")
    assert.ok(!isSensitivePath("C:\\proj\\notes.txt"), "plain file")
})

test("norm tolerates non-strings", () => {
    assert.doesNotThrow(() => g.norm(["a", "b"]))
})

// ─────────────────────────────────────────────────────────────────────────────
test("smoke: real factory — before blocks .env and after redacts output", async () => {
    const factory = await loadFactory()
    const hooks = await factory({ client: {}, directory: "/tmp" })

    await assert.rejects(
        () =>
            hooks["tool.execute.before"](
                { tool: "bash", sessionID: "s", callID: "c" },
                { args: { command: "cat .env" } },
            ),
        /blocked/,
    )

    const secret = "api_key=" + "Xy9kQ2mN7vR4tW8zB5c"
    const output: any = { title: "run", output: secret, metadata: { note: secret } }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c", args: {} }, output)
    assert.ok(!output.output.includes("Xy9kQ2mN7vR4tW8zB5c"), "output not redacted")
    assert.ok(!JSON.stringify(output.metadata).includes("Xy9kQ2mN7vR4tW8zB5c"), "metadata not redacted")

    // idempotency: the factory registers only once per project root (loadedRoots registry)
    const again = await factory({ client: {}, directory: "/tmp" })
    assert.deepEqual(again, {}, "second invocation should return {}")
})

test("entry point exports exactly SecurityGuard", async () => {
    const mod = await import("../../src/index.ts")
    assert.deepEqual(Object.keys(mod), ["SecurityGuard"])
})
