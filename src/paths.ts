/**
 * paths.ts — sensitive paths: regex detection and on-disk verification.
 * Matches the active guard log (and its `.1` rotation) dynamically, so a
 * relocated project log stays protected, and treats `.security-guard/**` as
 * sensitive project-local state.
 */
import * as fsx from "node:fs"
import { isGuardLogPathFor, LOG_FILE, norm, writeLog } from "./config.ts"
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

export type DiskInspectionReason = "not-file" | "too-large" | "metadata-failed" | "dangling-link" | "read-failed"
export type DiskInspection =
    | { readonly status: "missing" | "clean" | "contains-secrets" }
    | { readonly status: "unverifiable"; readonly reason: DiskInspectionReason }

export interface DiskInspectionOps {
    readonly lstatSync: (file: string) => fsx.Stats
    readonly statSync: (file: string) => fsx.Stats
    readonly readFileSync: (file: string, encoding: "utf8") => string
}

const DEFAULT_DISK_INSPECTION_OPS: DiskInspectionOps = {
    lstatSync: (file) => fsx.lstatSync(file),
    statSync: (file) => fsx.statSync(file),
    readFileSync: (file, encoding) => fsx.readFileSync(file, encoding),
}

function errorCode(error: unknown): string | undefined {
    if (typeof error !== "object" || error === null || !("code" in error)) return undefined
    const code = (error as { code?: unknown }).code
    return typeof code === "string" ? code : undefined
}

/**
 * Classifies a target before a full rewrite. Only a missing initial directory
 * entry is safe to treat as a new file; every other inspection failure fails closed.
 */
export function inspectDiskTarget(file: string, ops: DiskInspectionOps = DEFAULT_DISK_INSPECTION_OPS): DiskInspection {
    let entry: fsx.Stats
    try {
        entry = ops.lstatSync(file)
    } catch (error) {
        return errorCode(error) === "ENOENT"
            ? { status: "missing" }
            : { status: "unverifiable", reason: "metadata-failed" }
    }

    let stat = entry
    if (entry.isSymbolicLink()) {
        try {
            stat = ops.statSync(file)
        } catch (error) {
            return errorCode(error) === "ENOENT"
                ? { status: "unverifiable", reason: "dangling-link" }
                : { status: "unverifiable", reason: "metadata-failed" }
        }
    }

    if (!stat.isFile()) return { status: "unverifiable", reason: "not-file" }
    if (stat.size > DISK_SCAN_MAX_BYTES) return { status: "unverifiable", reason: "too-large" }

    try {
        return scan(ops.readFileSync(file, "utf8")).hits.length > 0
            ? { status: "contains-secrets" }
            : { status: "clean" }
    } catch {
        return { status: "unverifiable", reason: "read-failed" }
    }
}
