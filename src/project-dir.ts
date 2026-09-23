/**
 * project-dir.ts — project-local `.security-guard/` bootstrap: creates the
 * directory, keeps it out of version control (without ignoring the examples),
 * writes the examples once and points the guard log at the project path (with
 * fallback). Every step is independently fail-open. Internal deps:
 * `config.ts` (LOG_FILE, setLogFile, writeLog).
 */
import * as fsx from "node:fs"
import * as p from "node:path"
import { LOG_FILE, setLogFile, logPath, writeLog, type ProjectLogWriter } from "./config.ts"

/** Directory name under the project root. */
export const SECURITY_GUARD_DIR = ".security-guard"

const PROJECT_CONTENT_IGNORE = "/.security-guard/*"
const HALT_EXAMPLE_IGNORE = "!/.security-guard/halt.example"

/** Ignore the contents while keeping the examples versionable. */
const IGNORE_BLOCK =
    "# security-guard (project-local state)\n" +
    `${PROJECT_CONTENT_IGNORE}\n` +
    "!/.security-guard/blacklist.example\n" +
    `${HALT_EXAMPLE_IGNORE}\n`

/** Halt sentinel: the plugin checks only for the file's presence. */
export const HALT_FILE = "halt"

/** How to disable the guard, shipped next to the halt sentinel. */
const HALT_EXAMPLE =
    "plugin disabled\n" +
    "\n" +
    "# security-guard halt (example)\n" +
    "#\n" +
    '# Copy this file to "halt" to disable security-guard in this project.\n' +
    "# The plugin only checks that the file exists; the first line above is\n" +
    '# informational. Delete "halt" to re-enable the guard.\n'

/** Grammar guide shipped next to the team-owned blacklist. */
const EXAMPLE =
    "# security-guard team blacklist (example)\n" +
    "#\n" +
    '# Copy this file to "blacklist" and declare one term per line. Terms are\n' +
    "# matched case-insensitively as substrings and redacted before inference.\n" +
    "#\n" +
    "# Lines starting with # are comments; blank lines are ignored.\n" +
    "# Every other term is matched case-insensitively as a literal substring.\n" +
    "# Regex metacharacters (e.g. *) are literal characters; regex syntax is\n" +
    "# not supported. Lines prefixed with re: are ignored and logged.\n" +
    "#\n" +
    "# Examples:\n" +
    "# AcmeProjectCodename\n" +
    "# internal.acme.example\n" +
    "# acme-[0-9]{4}\n" +
    "# apikey_[0-9a-f]+\n"

/** Logger injected by the owning instance; standalone use keeps the globals. */
export interface BootstrapLog {
    /** Current log file (read at use time; mutated by relocation). */
    readonly file: string
    /** Relocates the log file (best-effort parent directory). */
    setFile(path: string): void
    readonly writeLog: ProjectLogWriter
    readonly logPath: (path: string) => string
}

export type BootstrapOpts = {
    /** Relocate the log into the directory (default `true`; skipped on override). */
    relocateLog?: boolean
    /** Owning instance's logger (defaults to the module-global logger). */
    log?: BootstrapLog
}

export type BootstrapResult = {
    /** `<root>/.security-guard`. */
    dir: string
    /** Active log path after the bootstrap. */
    log: string
    /** Directory created (`false` when it already existed or failed). */
    created: boolean
    /** The directory is git-ignored (block present or self-ignoring file). */
    ignored: boolean
    /** `blacklist.example` written by this run. */
    example: boolean
    /** `halt.example` written by this run. */
    haltExample: boolean
}

/**
 * Stable, step-derived error code. The caught error is intentionally not
 * inspected: platform messages embed absolute paths.
 */
const BOOTSTRAP_ERROR_CODE: Record<string, string> = {
    directory: "mkdir-failed",
    gitignore: "write-failed",
    "blacklist.example": "write-failed",
    "halt.example": "write-failed",
    log: "write-failed",
}

/** Returns the stable diagnostic code for a bootstrap step. */
export const bootstrapErrorCode = (step: string): string => BOOTSTRAP_ERROR_CODE[step] ?? "io-error"

const fail = (log: BootstrapLog, step: string): void => {
    log.writeLog("warn", "project-dir.failed", { step, error: bootstrapErrorCode(step) })
}

/** True when any line already references `.security-guard` (legacy lines included). */
const referencesProjectDir = (content: string): boolean =>
    content.split(/\r?\n/).some((line) => /^\/?\.security-guard/.test(line.trim()))

const hasGitignoreLine = (content: string, expected: string): boolean =>
    content.split(/\r?\n/).some((line) => line.trim() === expected)

/**
 * Ensures the directory is ignored. An existing `.gitignore` is extended only
 * when it does not already reference `.security-guard`; a missing root
 * `.gitignore` is created only inside a VCS worktree, otherwise the directory
 * ignores itself.
 */
function ensureIgnored(root: string, dir: string): boolean {
    const gitignore = p.join(root, ".gitignore")
    let existing: string | null = null
    try {
        existing = fsx.readFileSync(gitignore, "utf8")
    } catch {
        existing = null // missing; an unreadable file fails open on the write below
    }
    if (existing !== null) {
        if (referencesProjectDir(existing)) {
            // Upgrade the generated rule from older versions without touching
            // legacy parent-directory rules that cannot unignore children.
            if (
                hasGitignoreLine(existing, PROJECT_CONTENT_IGNORE) &&
                !hasGitignoreLine(existing, HALT_EXAMPLE_IGNORE)
            ) {
                const prefix = existing === "" || existing.endsWith("\n") ? "" : "\n"
                fsx.appendFileSync(gitignore, `${prefix}${HALT_EXAMPLE_IGNORE}\n`, "utf8")
            }
            return true
        }
        const prefix = existing === "" || existing.endsWith("\n") ? "" : "\n"
        fsx.appendFileSync(gitignore, prefix + IGNORE_BLOCK, "utf8")
        return true
    }
    if (fsx.existsSync(p.join(root, ".git"))) {
        fsx.writeFileSync(gitignore, IGNORE_BLOCK, "utf8")
        return true
    }
    fsx.writeFileSync(p.join(dir, ".gitignore"), "*\n", "utf8")
    return true
}

/** Writes `blacklist.example` unless it already exists. */
function writeExample(dir: string): boolean {
    const example = p.join(dir, "blacklist.example")
    if (fsx.existsSync(example)) return false
    fsx.writeFileSync(example, EXAMPLE, "utf8")
    return true
}

/** Writes `halt.example` unless it already exists. */
function writeHaltExample(dir: string): boolean {
    const example = p.join(dir, `${HALT_FILE}.example`)
    if (fsx.existsSync(example)) return false
    fsx.writeFileSync(example, HALT_EXAMPLE, "utf8")
    return true
}

/**
 * Bootstraps `<root>/.security-guard/`: directory, git ignore, blacklist
 * example and project log. Fail-open by design: a failing step is logged as
 * `project-dir.failed` and the remaining steps still run; the hook map is
 * never affected.
 */
export function bootstrapProjectDir(root: string, opts: BootstrapOpts = {}): BootstrapResult {
    const dir = p.join(root, SECURITY_GUARD_DIR)
    const L: BootstrapLog = opts.log ?? {
        get file() {
            return LOG_FILE
        },
        setFile: setLogFile,
        writeLog,
        logPath,
    }
    const result: BootstrapResult = {
        dir,
        log: L.file,
        created: false,
        ignored: false,
        example: false,
        haltExample: false,
    }

    try {
        fsx.mkdirSync(dir, { recursive: true })
        result.created = true
    } catch {
        fail(L, "directory")
    }

    try {
        result.ignored = ensureIgnored(root, dir)
    } catch {
        fail(L, "gitignore")
    }

    try {
        result.example = writeExample(dir)
    } catch {
        fail(L, "blacklist.example")
    }

    try {
        result.haltExample = writeHaltExample(dir)
    } catch {
        fail(L, "halt.example")
    }

    try {
        // An explicit log path or a failed directory keeps the previous log.
        if (result.created && (opts.relocateLog ?? true) && !process.env.SECURITY_GUARD_LOG) {
            L.setFile(p.join(dir, "security-guard.log"))
        }
    } catch {
        fail(L, "log")
    }

    result.log = L.file
    L.writeLog("info", "project-dir.ready", { root: L.logPath(root), log: L.logPath(L.file) })
    return result
}
