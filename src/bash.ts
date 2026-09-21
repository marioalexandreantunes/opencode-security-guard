/**
 * bash.ts — shell command analysis heuristics (including network verbs).
 */
import { MARKER } from "./config.ts"
import { isSensitivePath } from "./paths.ts"

// ─────────────────────────────────────────────────────────────────────────────
// Data-driven, named pattern categories. Module-private: they are composed into
// the exported regexes below, so the public surface stays a few RegExps.
// ─────────────────────────────────────────────────────────────────────────────

/** Process-environment / shell-variable dumps (POSIX, PowerShell, cmd). */
const ENV_DUMP_PATTERNS: string[] = [
    // `printenv` always reads: any argument is a variable name.
    "(?:^|[;&|]\\s*)printenv\\b[^;&|]*(?:$|[;&|])",
    // `env` dumps only when followed solely by flags/assignments (no command word):
    // `-u`/`--unset` consume one argument; a trailing `NAME=value` prints the env.
    // `[\w-]*` lets the unit be a bare `-`/`--` (end-of-options dumps).
    "(?:^|[;&|]\\s*)env\\b(?:\\s+(?:-{1,2}[\\w-]*|(?:-u|--unset)\\s+[^\\s;&|]+|[A-Za-z_]\\w*=[^\\s;&|]*))*\\s*(?:$|[;&|])",
    // Bare `set` dumps; `set -o <option>` is an option set, not a dump.
    "(?:^|[;&|]\\s*)set\\b\\s*(?:$|[;&|])",
    "\\bGet-Item\\s+Env:",
    "\\bGet-ChildItem\\s+Env:",
    "\\[Environment\\]::GetEnvironmentVariable",
    "\\bcmd(?:\\.exe)?\\s+/c\\s+set\\b",
]

/** Shell-variable listings (`declare -p`, `readonly -p`, `compgen -v`, …). */
const VAR_LIST_PATTERNS: string[] = ["\\b(?:export|declare|typeset|readonly)\\s+-p\\b", "\\bcompgen\\s+-v\\b"]

/** Interpreter env reads (≥9 languages). */
const INTERPRETER_ENV_PATTERNS: string[] = [
    "\\bos\\.environ\\b",
    "\\bos\\.getenv\\s*\\(",
    "\\bprocess\\.env\\b",
    "\\bENV\\[",
    "\\$_(?:ENV|SERVER|GET|POST|COOKIE|REQUEST|FILES|SESSION)\\b",
    "\\bgetenv\\s*\\(",
    "%ENV\\b",
    "\\bSystem\\.getenv\\s*\\(",
    "\\bDeno\\.env\\b",
    "\\bos\\.Getenv\\s*\\(",
]

/** Command substitution / backticks carrying an env dump. */
const EVAL_BYPASS_PATTERNS: string[] = ["\\$\\([^)]*\\b(?:printenv|env|set)\\b", "`[^`]*\\b(?:printenv|env|set)\\b"]

/** Decoders — direct I/O (they matter only when a sensitive path is present). */
const DECODERS: string[] = ["base64", "openssl", "gpg", "xxd", "uudecode"]

/** Commands that read/write content directly (≥30). */
const FILE_PROCESSORS: string[] = [
    "cat",
    "bat",
    "less",
    "more",
    "head",
    "tail",
    "type",
    "Get-Content",
    "gc",
    "read",
    "source",
    "cp",
    "mv",
    "scp",
    "rsync",
    "dd",
    "tee",
    "install",
    "sed",
    "perl",
    "awk",
    "strings",
    "od",
    "copy",
    "move",
    "rename",
    "ren",
    "jq",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "zcat",
    "bzip2",
    "xz",
    "split",
    "tr",
    "cut",
    "iconv",
    ...DECODERS,
]

/** Interpreter file reads of (quoted) paths — checked on the raw command. */
const INTERPRETER_FILE_READ_PATTERNS: RegExp[] = [
    /\bopen\s*\(\s*['"`]([^'"`]+)['"`]/i,
    /\bfs\.readFileSync\s*\(\s*['"`]([^'"`]+)['"`]/i,
    /\bFile\.read\s*\(\s*['"`]([^'"`]+)['"`]/i,
    /\breadfile\s*\(\s*['"`]([^'"`]+)['"`]/i,
]

/**
 * Builds a regex from named patterns, with an optional cheap keyword lookahead:
 * when no keyword is present the heavy alternation is never evaluated. The
 * gate is permissive (a false positive only costs work, never a wrong block).
 * `word` anchors the whole alternation with `\b` so a verb cannot match inside
 * an ordinary word (e.g. `od` inside `node`).
 */
function compose(patterns: string[], gate?: string, word = false): RegExp {
    const verbs = patterns.join("|")
    const body = word ? `\\b(?:${verbs})\\b` : `(?:${verbs})`
    const prefix = gate ? `(?=[\\s\\S]*(?:${gate}))` : ""
    return new RegExp(prefix + body, "i")
}

// The gate covers every keyword the composed patterns can require.
const ENV_DUMP_GATE = "env|printenv|set|compgen|getenv|environ|process|ENV|Deno|Environment|Env:|cmd|\\$_"

/** Any env/variable dump: POSIX, PowerShell, cmd, interpreters and eval bypass. */
export const ENV_DUMP = compose(
    [...ENV_DUMP_PATTERNS, ...INTERPRETER_ENV_PATTERNS, ...EVAL_BYPASS_PATTERNS],
    ENV_DUMP_GATE,
)
/** Shell variable listings: `export -p`, `declare -p`, `readonly -p`, `compgen -v`. */
export const ENV_EXPORT = compose(VAR_LIST_PATTERNS, "-p|compgen")
export const PS_ENV = /(\$env:|\b(?:Get-ChildItem|gci|dir|ls|Write-Output)\s+env:\S*|\bEnv:\w+)/i

/**
 * No /i flag on purpose: only UPPERCASE names count as env vars.
 * `$key` is no longer a false positive; `$API_TOKEN` and `$env:SECRET` are.
 */
export const ENV_ECHO =
    /\b(?:[Ee]cho|[Pp]rintf|[Cc]url|[Ww]get|[Ii]wr|Invoke-WebRequest)\b[^;&|]*\$\{?(?:env:)?[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASS|PWD|CRED|URL|DSN|CONN|HOST)[A-Z0-9_]*\}?/

/** Operations that write to disk (PowerShell + POSIX). */
export const WRITE_VERB =
    /(?<![-=<>!$])\d?>>?(?!\s*[=&|])\s*[^\s&|>]|\b(?:Set-Content|Add-Content|Out-File|New-Item|Copy-Item|Move-Item|Rename-Item|copy|move|rename|ren|tee|dd|install)\b|\b(?:sed|perl|awk)\b[^;&|]*-i/i

/** Writes through interpreters or downloads (marker-writeback bypass). */
export const API_WRITE =
    /\b(?:python3?|node|deno|bun|ruby|php)\b[^;&|]*(?:open\s*\(|writeFile|\.write\s*\(|fs\.write)|\b(?:curl|wget)\b[^;&|]*(?:\s-[oO]\b|\s--output\b)/i

/** `<MARKER:type:hash>` — the trailing `>` is not a shell redirection. */
export const MARKER_RE = new RegExp(`<${MARKER}:[^>]{0,64}>`, "g")

/** Network / exfiltration verbs: if a marker appears with one of these, block. */
export const NET_VERB =
    /\b(?:curl|wget|ncat|netcat|ssh|scp|sftp|rsync|telnet|ftp|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|\bnc\b|\bgit\s+(?:push|remote|fetch)\b|\bdocker\s+push\b|\bgh\s+(?:release|api|gist)\b|\baws\s+s3\b|\/dev\/tcp\//i

/**
 * Commands that read/write content directly (they block sensitive paths).
 * The verb list doubles as its own keyword pre-filter.
 */
export const IO_CMDS = compose(FILE_PROCESSORS, undefined, true)

/**
 * Tokenizes the command and tests each token as a path. It only blocks when
 * there is direct I/O intent (a read/write command, a redirection, or a
 * `--*-file=` flag); low-risk commands (ls, git, grep, sort, diff) no longer
 * produce false positives — their output is redacted by the `after` hook.
 *
 * Quoted interpreter file reads (`open('.env')`) are checked on the raw
 * command first, because the tokenizer strips quoted strings.
 */
export function sensitiveToken(cmd: string): string | null {
    for (const re of INTERPRETER_FILE_READ_PATTERNS) {
        const match = re.exec(cmd)
        if (match?.[1] && isSensitivePath(match[1])) return match[1]
    }
    const bare = cmd.replace(/"[^"]*"|'[^']*'/g, " ")
    const direct = IO_CMDS.test(bare) || /[<>]/.test(bare)
    const flagFile = /--?[\w-]*(?:file|config)=/i.test(cmd)
    for (const t of cmd.split(/[\s;&|<>()'"`=:]+/)) {
        const c = t.replace(/^-+/, "").replace(/[*?[\]]+$/, "")
        if (c.length <= 2) continue
        if (isSensitivePath(c) && (direct || flagFile)) return c
    }
    return null
}
