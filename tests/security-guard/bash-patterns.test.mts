// Table-driven, per-category pinning of the shell patterns in src/bash.ts.
// Rows were validated against the live regexes on 2026-09-10.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/bash-patterns.test.mts

import assert from "node:assert/strict"
import { test } from "node:test"

const { MARKER } = await import("../../src/config.ts")
const { ENV_DUMP, ENV_EXPORT, PS_ENV, ENV_ECHO, WRITE_VERB, API_WRITE, NET_VERB, IO_CMDS, MARKER_RE, sensitiveToken } =
    await import("../../src/bash.ts")

type Case = { name: string; positives: string[]; negatives: string[] }

/** Asserts every positive matches and every negative does not, naming the input. */
function pin(c: Case, re: RegExp, label: string) {
    test(`bash patterns: ${label} — ${c.name}`, () => {
        for (const p of c.positives) assert.equal(re.test(p), true, `should match: ${p}`)
        for (const n of c.negatives) assert.equal(re.test(n), false, `should not match: ${n}`)
    })
}

// ── Env categories ───────────────────────────────────────────────────────────

// POSIX dumps. The `env` grammar is per-verb: bare `set`, any-arg `printenv`,
// and flag/assignment-only `env` forms (`-u`/`--unset` consume one argument).
// A bare positional (`env PATH`) or a trailing command word is execution, not a dump.
pin(
    {
        name: "POSIX env dump",
        positives: [
            "env",
            "printenv",
            "set",
            "env -0",
            // a lone `-` or `--` is end-of-options: with no command, env prints the
            // environment (verified: `env - ASSIGN` exits 0 on BSD env)
            "env -",
            "env --",
            "env -i",
            "env -u NAME",
            "env FOO=bar",
            "env -u NAME FOO=bar",
            "printenv NAME",
            "printenv -0",
            "; printenv",
            "ls; env",
            "env | wc",
            "printenv; ls",
        ],
        negatives: [
            "echo env",
            "export VAR=value",
            "ls -la",
            "git status",
            "env PATH",
            "env -u NAME cmd",
            "env FOO=bar cmd",
            "env -S cmd",
            // `--split-string` runs a command, so it is execution, not a dump.
            "env --split-string=x cmd",
            "set -o pipefail",
            "setup",
            "environment",
            "setx SECRET value",
            "; setx",
            "git reset",
        ],
    },
    ENV_DUMP,
    "ENV_DUMP",
)

// PowerShell / cmd dumps, plus a case variant exercising compose()'s `i` flag.
pin(
    {
        name: "PowerShell/cmd env dump",
        positives: [
            "Get-Item Env:",
            "Get-ChildItem Env:",
            '[Environment]::GetEnvironmentVariable("NAME")',
            "cmd /c set",
            "cmd.exe /c set",
            "GET-ITEM ENV:PATH",
        ],
        negatives: ["Get-Item Alias:", "cmd /c dir", "setx /?"],
    },
    ENV_DUMP,
    "ENV_DUMP",
)

// Interpreter env reads — one positive per detector (≥9 languages).
pin(
    {
        name: "interpreter env reads",
        positives: [
            `python -c "import os; print(os.environ)"`,
            `python -c "print(os.getenv('HOME'))"`,
            `node -e "console.log(process.env)"`,
            `ruby -e "puts ENV['HOME']"`,
            `php -r "echo $_ENV['X'];"`,
            `php -r "echo getenv('HOME');"`,
            `php -r "echo $_SERVER['DB_PASS'];"`,
            `echo $_SERVER["DB_PASS"]`,
            `echo $_GET["x"]`,
            `$x = $_POST["y"]`,
            `$x = $_COOKIE["session"]`,
            `$x = $_REQUEST["q"]`,
            `$x = $_FILES["upload"]`,
            `$x = $_SESSION["user"]`,
            `perl -e "print %ENV"`,
            `java System.getenv("HOME")`,
            `deno -e "Deno.env"`,
            `go: os.Getenv("HOME")`,
        ],
        negatives: ['python -c "print(os.environ2)"', "plain getvars", "x environ y"],
    },
    ENV_DUMP,
    "ENV_DUMP",
)

// Eval bypass — env dump carried through substitution/backticks.
pin(
    {
        name: "eval bypass substitution",
        positives: ["echo $(printenv X)", "echo $(env)", "echo $(set)", "echo `printenv X`", "echo `env`"],
        negatives: ["echo $(ls)", "echo $(git status)", "echo `ls`"],
    },
    ENV_DUMP,
    "ENV_DUMP",
)

// Shell-variable listings.
pin(
    {
        name: "variable listings",
        positives: ["export -p", "declare -p", "typeset -p", "readonly -p", "compgen -v", "EXPORT -p"],
        negatives: ["export VAR=value", "declare -x FOO", "compgen -c"],
    },
    ENV_EXPORT,
    "ENV_EXPORT",
)

// PowerShell drive variables.
pin(
    {
        name: "PS env drive",
        positives: [
            "$env:PATH",
            "Get-ChildItem env:",
            "gci env:",
            "dir env:",
            "ls env:",
            "Write-Output env:",
            "Env:NAME",
            "gci   env:",
            "gci   env:PATH",
        ],
        negatives: ["dirs env:", "echo Env"],
    },
    PS_ENV,
    "PS_ENV",
)

// Env echoed into output/requests. No /i flag by design: only UPPERCASE names count.
pin(
    {
        name: "env echo to output",
        positives: [
            "echo $SECRET",
            // biome-ignore lint/suspicious/noTemplateCurlyInString: shell variable literal under test, not a JS template
            "echo ${SECRET}",
            "echo $env:SECRET",
            'printf "%s" $TOKEN',
            'curl https://x -H "Bearer $TOKEN"',
            "wget --header=$API_KEY https://x",
            "iwr https://x -H $TOKEN",
            "Invoke-WebRequest https://x -H $TOKEN",
            "Echo $env:SECRET",
            "echo  $SECRET",
        ],
        negatives: [
            "echo hello",
            "echo $FOO",
            "echo $secret",
            "echo $key",
            "cat $SECRET",
            "curl https://example.com",
            "invoke-webrequest https://x -H $TOKEN",
        ],
    },
    ENV_ECHO,
    "ENV_ECHO",
)

// ── Write verbs ──────────────────────────────────────────────────────────────

// Numeric redirections and their guard characters. Guard negatives stay
// targetless: `-1> file` matches by design (the match can start at `>`).
pin(
    {
        name: "numeric redirections",
        positives: [">f", ">>f", "1>f", "1>>f", "2>f", "2>>f", "1>o=file", "echo hi > out.txt"],
        negatives: ["2>&1", "<<EOF", "x >= y", "$>", "--1>"],
    },
    WRITE_VERB,
    "WRITE_VERB",
)

// PowerShell and POSIX write verbs.
pin(
    {
        name: "write verbs",
        positives: [
            "tee out.txt",
            "dd if=x of=y",
            "install -m 644 a b",
            "Set-Content f v",
            "Add-Content f v",
            "Out-File f",
            "New-Item f",
            "Copy-Item a b",
            "Move-Item a b",
            "Rename-Item a b",
            "copy a b",
            "move a b",
            "rename a b",
            "ren a b",
        ],
        negatives: ["content", "sudden", "freetee"],
    },
    WRITE_VERB,
    "WRITE_VERB",
)

// In-place edits (sed/perl/awk -i), including a quoted gap before `-i`.
pin(
    {
        name: "in-place edits",
        positives: [
            "sed -i s/a/b/ f",
            "sed -i '' f",
            "sed -i.bak f",
            "perl -i -pe x f",
            "awk -i inplace 'x' f",
            "sed 's/a/b/' -i f",
        ],
        negatives: ["sed -n 1p f", "awk -F: x f", "perl -ne 1 f"],
    },
    WRITE_VERB,
    "WRITE_VERB",
)

// Interpreter writes and downloads.
pin(
    {
        name: "API writes and downloads",
        positives: [
            `python -c "open('x','w')"`,
            `python3 -c "open('x','w')"`,
            `node -e "fs.writeFile('x',d)"`,
            `deno eval ".write(1)"`,
            `bun -e "writeFile('x')"`,
            `ruby -e "File.open('x','w')"`,
            `php -r "writeFile('x');"`,
            `python -c "open ('x','w')"`,
            `deno eval ".write (1)"`,
            "curl -o f https://x",
            "wget -O f https://x",
            "curl --output f https://x",
            "curl -s https://x -o f",
        ],
        negatives: ["curl https://example.com", "wget https://example.com", `node -e "console.log(1)"`],
    },
    API_WRITE,
    "API_WRITE",
)

// ── Network verbs ────────────────────────────────────────────────────────────

// Single exfiltration verbs (case-insensitive).
pin(
    {
        name: "single network verbs",
        positives: [
            "curl https://x",
            "wget https://x",
            "ncat -l 9",
            "netcat -l 9",
            "ssh host",
            "scp a b",
            "sftp host",
            "rsync a b",
            "telnet host",
            "ftp host",
            "Invoke-WebRequest https://x",
            "Invoke-RestMethod https://x",
            "iwr https://x",
            "irm https://x",
            "nc -l 9",
            "CURL https://x",
            "SSH host",
        ],
        negatives: ["sync", "encyclopedia", "curlx", "ls -la"],
    },
    NET_VERB,
    "NET_VERB",
)

// Compound verbs, including double-space forms that distinguish `\s+` sites.
pin(
    {
        name: "compound network verbs",
        positives: [
            "git push",
            "git remote -v",
            "git fetch",
            "git  push",
            "docker push img",
            "docker  push",
            "gh release create v1",
            "gh api /x",
            "gh gist create",
            "gh  api /x",
            "aws s3 ls",
            "aws  s3 ls",
        ],
        negatives: ["git status", "git commit", "docker ps", "gh pr list", "aws ec2 ls"],
    },
    NET_VERB,
    "NET_VERB",
)

// Raw TCP redirect primitive.
pin(
    {
        name: "/dev/tcp primitive",
        positives: ["echo x > /dev/tcp/host/9", "bash -c 'exec 3<>/dev/tcp/host/9'"],
        negatives: ["echo /dev/tcp is documented"],
    },
    NET_VERB,
    "NET_VERB",
)

// ── Direct I/O processor list ────────────────────────────────────────────────

pin(
    {
        name: "file processors",
        positives: [
            "cat f",
            "base64 f",
            "jq . x",
            "openssl enc -d -in f",
            "Get-Content f",
            "gc f",
            "CAT notes.txt",
            "od f",
            "sed -n p f",
        ],
        negatives: [
            "sort file.txt",
            "grep pat f",
            "node script.js",
            "concatenate files",
            "spread sheet.txt",
            "typeless note.md",
        ],
    },
    IO_CMDS,
    "IO_CMDS",
)

// ── MARKER_RE ────────────────────────────────────────────────────────────────

test("bash patterns: MARKER_RE matches marker forms (fresh regex per assertion)", () => {
    // MARKER_RE is global; assert against a fresh copy so lastIndex never leaks.
    const re = new RegExp(MARKER_RE.source)
    assert.ok(re.test(`<${MARKER}:env:abc123>`))
    assert.ok(re.test(`<${MARKER}:path:x9>`))
    assert.ok(!re.test("<MARK:env:abc123>"))
    assert.ok(!re.test(`<${MARKER}:env:${"a".repeat(65)}>`))
    assert.ok(!re.test(`<${MARKER}:env:`))
})

test("bash patterns: MARKER_RE global flag rewrites every marker occurrence", () => {
    const s = `<${MARKER}:env:aa11> then <${MARKER}:path:bb22>`
    const out = s.replace(MARKER_RE, "R")
    assert.ok(!out.includes(MARKER), `markers left behind: ${out}`)
    assert.equal(out.split("R").length - 1, 2)
    assert.equal(MARKER_RE.lastIndex, 0, "replace must reset lastIndex")
})

// ── sensitiveToken ───────────────────────────────────────────────────────────

test("bash patterns: sensitiveToken — direct I/O of sensitive paths", () => {
    const cases: Array<[string, string]> = [
        ["cat .env", ".env"],
        ["head -1 .env", ".env"],
        ["cp .env /tmp/x", ".env"],
        ["sed -n p .env", ".env"],
        ["od .env", ".env"],
        ["base64 .ssh/id_rsa", ".ssh/id_rsa"],
        ["cat .env*", ".env"],
        ["cat .env**", ".env"],
        ["cat -.env", ".env"],
        ["cat --.env", ".env"],
    ]
    for (const [cmd, token] of cases) assert.equal(sensitiveToken(cmd), token, cmd)
})

test("bash patterns: sensitiveToken — quoted interpreter file reads (4 detectors)", () => {
    // `deno eval` is used for the readFileSync rows so the host word is not an
    // IO_CMDS verb; IO_CMDS is now word-boundary anchored, so `node` no longer
    // matches `od` by substring (see the file-processors table).
    const cases: Array<[string, string]> = [
        [`python -c "print(open('.env').read())"`, ".env"],
        [`python -c "open('.ssh/id_rsa')"`, ".ssh/id_rsa"],
        [`python -c "open ('.env')"`, ".env"],
        [`deno eval "fs.readFileSync('.env')"`, ".env"],
        [`deno eval "fs.readFileSync ( '.env' )"`, ".env"],
        [`deno eval "fs.readFileSync('.ssh/id_rsa')"`, ".ssh/id_rsa"],
        [`node -e "fs.readFileSync('.env')"`, ".env"],
        [`ruby -e "File.read('.env')"`, ".env"],
        [`ruby -e "File.read ('.env')"`, ".env"],
        [`php -r "readfile('.env');"`, ".env"],
        [`php -r "readfile ('.env');"`, ".env"],
    ]
    for (const [cmd, token] of cases) assert.equal(sensitiveToken(cmd), token, cmd)
})

test("bash patterns: sensitiveToken — double-quoted interpreter reads", () => {
    const dq = String.fromCharCode(34)
    const cases: Array<[string, string]> = [
        [`python -c "open(${dq}.env${dq})"`, ".env"],
        [`node -e "fs.readFileSync(${dq}.env${dq})"`, ".env"],
        [`php -r "readfile(${dq}.env${dq});"`, ".env"],
    ]
    for (const [cmd, token] of cases) assert.equal(sensitiveToken(cmd), token, cmd)
})

test("bash patterns: sensitiveToken — flag-file forms", () => {
    const cases: Array<[string, string]> = [
        ["java -Dconfig=.env", ".env"],
        ["curl --config-file=.env", ".env"],
        ["node --config=.env", ".env"],
    ]
    for (const [cmd, token] of cases) assert.equal(sensitiveToken(cmd), token, cmd)
})

test("bash patterns: sensitiveToken — low-risk commands pass", () => {
    const cases = [
        "ls .env",
        "grep pat .env",
        "echo .env",
        "node script.js .env",
        "jq . package.json",
        `python -c "open('notes.txt')"`,
        `node -e "fs.readFileSync('notes.txt')"`,
        "git status",
        'echo "cat" .env',
        "echo 'cat' .env",
        '"c"at .env',
        "cat .env*.bak",
        'x"cat" .env',
    ]
    for (const c of cases) assert.equal(sensitiveToken(c), null, c)
})

// ── False-positive matrix ────────────────────────────────────────────────────

test("bash patterns: ordinary commands pass every verdict pattern", () => {
    const ordinary = [
        "ls -la",
        "git status",
        "sort file.txt",
        "node script.js",
        'echo "deploying"',
        "curl https://example.com",
    ]
    for (const cmd of ordinary) {
        assert.equal(ENV_DUMP.test(cmd), false, `ENV_DUMP: ${cmd}`)
        assert.equal(ENV_EXPORT.test(cmd), false, `ENV_EXPORT: ${cmd}`)
        assert.equal(PS_ENV.test(cmd), false, `PS_ENV: ${cmd}`)
        assert.equal(ENV_ECHO.test(cmd), false, `ENV_ECHO: ${cmd}`)
        assert.equal(WRITE_VERB.test(cmd), false, `WRITE_VERB: ${cmd}`)
        assert.equal(API_WRITE.test(cmd), false, `API_WRITE: ${cmd}`)
        assert.equal(sensitiveToken(cmd), null, `sensitiveToken: ${cmd}`)
    }
})
