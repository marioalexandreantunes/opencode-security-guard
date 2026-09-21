/**
 * paths.ts — sensitive paths: regex detection and on-disk verification.
 * Matches the active guard log (and its `.1` rotation) dynamically, so a
 * relocated project log stays protected, and treats `.security-guard/**` as
 * sensitive project-local state.
 */
import * as fsx from "node:fs"
import { norm, LOG_FILE, writeLog, isGuardLogPathFor } from "./config.ts"
import { scan } from "./rules.ts"
import { canonicalizeRoot, resolveCanonicalTarget } from "./write-policy.ts"

/** Escape a literal string so it can be embedded safely in a RegExp. */
export const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

/** Files that must never be read or written through a tool (case-insensitive). */
export const SENSITIVE_PATHS: RegExp[] = [
    /(^|\/)\.env(?:\.[a-z0-9_.-]+|rc)?$/i,
    /(^|\/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/i,
    /\.(pem|key|pfx|p12|jks|asc|ppk)$/i,
    /(^|\/)\.ssh\//i,
    /(^|\/)\.gnupg\//i,
    /(^|\/)\.aws\/(credentials|config)$/i,
    /(^|\/)\.kube\/config$/i,
    /(^|\/)\.(npmrc|netrc|pgpass|git-credentials|htpasswd)$/i,
    /(^|\/)\.docker\/config\.json$/i,
    /(^|\/)credentials(\.json)?$/i,
    /(^|\/)secrets?\.ya?ml$/i,
    /(^|\/)(shadow|wallet\.dat)$/i,
    // anchored: does not block `cargo test -p keystore-lib`
    /(^|\/)[^/]*keystore[^/]*\.(jks|p12|pfx|bks|keystore)$/i,

    // ─── licence file ───
    /(^|\/)license\.lic$/i,

    // ─── the log itself (and its rotation) ───
    // Matched dynamically against the live LOG_FILE in `isSensitivePath`, so a
    // relocated log (project-local bootstrap) is recognised without a restart.

    // ─── project-local state: the agent must not read or tamper with it ───
    /(^|\/)\.security-guard\//i,

    ...(process.env.SECURITY_GUARD_EXTRA_PATHS ?? "")
        .split(";")
        .map((part) => part.trim())
        .filter(Boolean)
        .map((pattern, index) => compileExtraPath(pattern, index))
        .filter((re): re is RegExp => re !== null),
]

/**
 * Compiles a user-supplied path regex. An invalid one is skipped and logged
 * with its position only — never the pattern or the engine message, both of
 * which would leak the configured term. `index` counts the non-empty, trimmed
 * candidates, so empty `;;` segments do not shift it.
 */
function compileExtraPath(pattern: string, index: number): RegExp | null {
    try {
        return new RegExp(pattern, "i")
    } catch {
        writeLog("warn", "config.invalid-path", { index, error: "invalid-regular-expression" })
        return null
    }
}

/** True when `n` is the active guard log or its `.1` rotation (case-insensitive). */
function isGuardLogPath(n: string): boolean {
    return isGuardLogPathFor(LOG_FILE, n)
}

/** True when the path matches the sensitive-file list. */
export function isSensitivePath(raw: string): boolean {
    const n = norm(raw)
    if (!n) return false
    if (isGuardLogPath(n)) return true
    return SENSITIVE_PATHS.some((re) => re.test(n))
}

/** Scope for an instance-aware sensitivity check. */
export interface SensitivityScope {
    /** Owning instance's active log file. */
    readonly logFile: string
    /** Owning instance's resolved project root (for canonicalization). */
    readonly root?: string
    /** Pre-resolved canonical root, to avoid re-inspecting the filesystem. */
    readonly canonicalRoot?: string | null
}

/**
 * Instance-aware sensitive-path check: the lexical union first (the exact
 * current behavior, without filesystem access), then the canonical target.
 * Fail-closed: an uninspectable root or target counts as sensitive.
 */
export function isSensitivePathFor(scope: SensitivityScope, raw: unknown): boolean {
    const lexical = norm(raw)
    if (!lexical) return false
    if (isGuardLogPathFor(scope.logFile, lexical)) return true
    if (SENSITIVE_PATHS.some((re) => re.test(lexical))) return true
    const root = scope.root ?? process.cwd()
    if ((scope.canonicalRoot ?? canonicalizeRoot(root)) === null) return true
    const canonical = resolveCanonicalTarget(root, lexical)
    if (canonical === null) return true
    if (isGuardLogPathFor(scope.logFile, canonical)) return true
    // `resolveCanonicalTarget` joins with platform-native separators (on Windows
    // `\`), while SENSITIVE_PATHS is written against `/`. Normalize before the
    // lexical test, or a junction/symlink target would escape the catalogue.
    return SENSITIVE_PATHS.some((re) => re.test(norm(canonical)))
}

/** Skip the on-disk secret scan above this size (too costly). */
export const DISK_SCAN_MAX_BYTES = 2 * 1024 * 1024

/**
 * Scans the file on disk for secrets, used before a full rewrite. Returns
 * `false` for missing files, non-files and files over `DISK_SCAN_MAX_BYTES`.
 */
export function diskHasSecrets(file: string): boolean {
    try {
        const stat = fsx.statSync(file)
        if (!stat.isFile() || stat.size > DISK_SCAN_MAX_BYTES) return false
        return scan(fsx.readFileSync(file, "utf8")).hits.length > 0
    } catch {
        return false // new file -> nothing to protect
    }
}
