// security-guard real-hook bash suite (C9).
// Drives the REAL tool.execute.before handler with recorded args instead of
// mirroring its decision sequence in the test.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/before-hook.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// Temp log before importing config (read at module load).
process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-before-log-")), "guard.log")

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER } = await import("../../src/config.ts")

const hooks = await SecurityGuard({ client: {}, directory: process.cwd() })

const run = (command: string) =>
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command } })
const blocked = (command: string) => assert.rejects(() => run(command), undefined, `should block: ${command}`)
const allowed = (command: string) => assert.doesNotReject(() => run(command), `should allow: ${command}`)
const mk = (rule: string, hash = "0123456789abcdef"): string => `<${MARKER}:${rule}:${hash}>`

// ── env and variable dumps ───────────────────────────────────────────────
test("shell: env and variable dumps are blocked", async () => {
    const cases = [
        "env",
        "printenv",
        "printenv API_TOKEN",
        "set",
        "env -0",
        "export -p",
        "declare -p",
        "typeset -p",
        "readonly -p",
        "compgen -v",
    ]
    for (const c of cases) await blocked(c)
})

test("shell: interpreter env reads are blocked (>=9 detectors)", async () => {
    const cases = [
        `python -c "import os; print(os.environ)"`,
        `python -c "print(os.getenv('HOME'))"`,
        `node -e "console.log(process.env)"`,
        `ruby -e "puts ENV['HOME']"`,
        `php -r "echo getenv('HOME');"`,
        `php -r "echo $_ENV['HOME'];"`,
        `perl -e 'print %ENV'`,
        `echo 'os.Getenv("HOME")' | go run /dev/stdin`,
        `java -e "System.getenv('HOME')"`,
        `deno -e "console.log(Deno.env.get('HOME'))"`,
    ]
    for (const c of cases) await blocked(c)
})

// ── file processors and sensitive paths ──────────────────────────────────
test("shell: file processors block sensitive paths only", async () => {
    const deny = [
        "sed -n p .env",
        "base64 .ssh/id_rsa",
        "jq . .env",
        "gpg -d .env",
        "tar -cf x.tar .env",
        "openssl enc -in .env",
    ]
    const pass = [
        "jq . package.json",
        "sed -n p file.txt",
        "tar -cf x.tar src/",
        "cut -d: -f1 /etc/hosts",
        "base64 README.md",
    ]
    for (const c of deny) await blocked(c)
    for (const c of pass) await allowed(c)
})

test("shell: quoted interpreter file reads of sensitive paths", async () => {
    await blocked(`python -c "print(open('.env').read())"`)
    await blocked(`node -e "fs.readFileSync('.env')"`)
    await allowed(`python -c "print(open('notes.txt').read())"`)
})

test("shell: substitution and pipe-to-shell bypasses", async () => {
    const deny = [
        "echo $(cat .env)",
        "echo $(printenv API_TOKEN)",
        "echo `printenv API_TOKEN`",
        "env | bash",
        "cat .env | bash",
        "base64 -d .env",
        "openssl enc -d -in secrets.yaml",
        "gpg -d .env",
    ]
    for (const c of deny) await blocked(c)
    await allowed("echo $(cat notes.txt)")
    await allowed("echo hi | bash")
})

// ── negative corpus ──────────────────────────────────────────────────────
test("shell: common dev commands pass", async () => {
    const pass = [
        "ls -la",
        "git status",
        "grep TODO src/",
        "cat README.md",
        "jq . package.json",
        "sed -n p file.txt",
        `grep -E "env|set" file`,
        `git commit -m "set up"`,
        "env FOO=bar node x",
        "set -e",
    ]
    for (const c of pass) await allowed(c)
})

test("shell: sensitive-token false positives stay clear", async () => {
    const pass = [
        "ls -la .env",
        "rm .env",
        "git diff .env",
        "sort .env",
        "diff .env .env.example",
        `git commit -m "fix .env"`,
        "grep credentials src/",
        `grep "BEGIN" key.pem`,
    ]
    for (const c of pass) await allowed(c)
})

test("shell: direct protections are kept", async () => {
    const deny = [
        "cat .env",
        "rtk read .env",
        "cp .env /tmp/x",
        "source .env",
        "cat ~/.ssh/id_rsa",
        "echo $API_TOKEN",
        "env",
        "printenv",
        "sed -i s/x/y/ .env",
    ]
    for (const c of deny) await blocked(c)
})

test("shell: expanded bypasses are closed", async () => {
    const deny = [
        `echo "${mk("jwt")}" 1> /tmp/f`,
        `echo "${mk("jwt")}" 2>> /tmp/f`,
        "cat .env*",
        "--env-file=.env",
        "docker run --env-file=.env img",
        "echo $DATABASE_URL",
        "gci env: | grep PASS",
        "Get-ChildItem Env:API_TOKEN",
    ]
    for (const c of deny) await blocked(c)
})

test("shell: Windows cmd file operations block sensitive paths", async () => {
    const deny = [
        "copy C:\\Users\\me\\.env D:\\leak",
        "move C:\\proj\\.ssh\\id_rsa D:\\x",
        "ren C:\\proj\\.npmrc backup",
        "rename C:\\proj\\.env .env.bak",
        "cp .env /tmp/x",
    ]
    for (const c of deny) await blocked(c)
    await allowed("copy C:\\proj\\notes.txt D:\\x")
})

test("shell: marker-writeback via cmd file operations is blocked", async () => {
    await blocked(`copy "${mk("jwt")}" D:\\x`)
    await blocked(`move "${mk("jwt")}" D:\\x`)
    await blocked(`ren "${mk("jwt")}" x`)
})

test("shell: marker-writeback stays blocked, echo to stdout allowed", async () => {
    await blocked(`echo "${mk("jwt")}" > /tmp/f`)
    await blocked(`python3 -c 'open("/tmp/f","w").write("${mk("jwt")}")'`)
    await allowed(`echo "${mk("jwt")}"`)
})

test("shell: PowerShell and cmd parity", async () => {
    const deny = [
        "Get-Item Env:",
        `[Environment]::GetEnvironmentVariable("API_KEY")`,
        "cmd /c set",
        "Get-ChildItem Env:",
        "gci env:",
    ]
    for (const c of deny) await blocked(c)
})

test("shell: block message names the coarse category", async () => {
    await assert.rejects(() => run("cat .env"), /\[sensitive file\]/)
    await assert.rejects(() => run("env"), /\[environment\/variable dump\]/)
    await assert.rejects(() => run("api_key=" + "Xy9kQ2mN7vR4tW8zB5c"), /\[secret in plain text\]/)
})
