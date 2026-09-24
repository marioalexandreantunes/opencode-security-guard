/**
 * config.ts — shared constants and utilities for security-guard.
 * No internal dependencies: base of the chain consumed by rules, redact, vault,
 * paths, bash, blacklist, project-dir and plugin. `LOG_FILE` is settable after
 * import through `setLogFile` (project-local log bootstrap).
 */

import { createHash, createHmac, randomBytes } from "node:crypto"
import * as fsx from "node:fs"
import * as os from "node:os"
import * as p from "node:path"

/** Placeholder prefix that replaces a secret: `<MARKER:rule:hash>`. */
export const MARKER = "SECURITY_GUARD_REDACTED"
/** `redact` (default) redacts on read; `block` also blocks sensitive-file reads. */
export const MODE = (process.env.SECURITY_GUARD_MODE ?? "redact").toLowerCase()
/** Plugin package version; mirrors `package.json` (kept in sync by a test). */
export const PLUGIN_VERSION = "0.1.0"
/** `1` disables toasts; logging continues regardless. */
export const QUIET = process.env.SECURITY_GUARD_QUIET === "1"
/** Rotate the log to a single `.1` backup once it exceeds 5 MiB. */
export const LOG_MAX = 5 * 1024 * 1024
/** Minimum gap between two toasts, in milliseconds. */
export const TOAST_COOLDOWN_MS = 4000

/**
 * Active log path. Never resolves under the user's home: the pre-bootstrap
 * default is the OS temp directory, and the plugin relocates it into
 * `<projectRoot>/.security-guard/` on load. If the temp directory is
 * unwritable the path is left as-is and `writeLog` warns once.
 */
export let LOG_FILE = process.env.SECURITY_GUARD_LOG ?? p.join(os.tmpdir(), "opencode-security-guard.log")

try {
    fsx.mkdirSync(p.dirname(LOG_FILE), { recursive: true })
} catch {
    // never let the plugin fail to load because of logging
    LOG_FILE = p.join(os.tmpdir(), "opencode-security-guard.log")
}

/**
 * Relocates the active log (project-local bootstrap, tests). Best-effort: the
 * parent directory is created when possible; on failure the previous path is
 * kept so logging never breaks.
 *
 * @internal Standalone/legacy sink; plugin instances relocate through
 * `setContextLogFile` on their own {@link ProjectContext}.
 */
export function setLogFile(path: string): void {
    if (!path) return
    try {
        fsx.mkdirSync(p.dirname(path), { recursive: true })
    } catch {
        return
    }
    LOG_FILE = path
}

/** Coerce any value to a string and normalize Windows separators to `/`. */
export const norm = (s: unknown): string => (typeof s === "string" ? s : String(s ?? "")).replace(/\\/g, "/")

/**
 * Pure marker-identity derivation: HMAC-SHA256 over the observed value with an
 * explicit key, truncated to 16 lowercase hex chars (64 bits). Exported so the
 * unlinkability property can be exercised with synthetic keys, without touching
 * the process key.
 */
export const createFingerprint = (key: string | Uint8Array, value: string): string =>
    createHmac("sha256", key).update(value).digest("hex").slice(0, 16)

/**
 * Per-process marker key: 32 random bytes generated once at import, held in
 * module memory and never exported, logged or embedded in markers.
 */
const PROCESS_KEY = randomBytes(32)

/**
 * Opaque marker identity of a secret. The same value maps to the same identity
 * within the process (idempotency) and to an unlinkable identity in another
 * process without the key, closing dictionary comparison of low-entropy values.
 */
export const fp = (v: string): string => createFingerprint(PROCESS_KEY, v)

/** Closed set of severity levels written to records (ranks live in LEVEL_RANK). */
export const LOG_LEVELS = ["debug", "info", "warn", "error"] as const
export type LogLevel = (typeof LOG_LEVELS)[number]

/**
 * Base for the module-global `logPath`. Instances sanitize through their own
 * {@link ProjectContext.logPath}; this base exists only for the standalone API.
 *
 * @internal
 */
let logBase = ""

/**
 * Sets the module-global `logPath` base. An empty root is ignored.
 *
 * @internal Standalone/test-only; plugin instances use `ProjectContext.logPath`
 * (the plugin never configures this base, so a forgotten `setLogBase` cannot
 * silently affect runtime behavior).
 */
export function setLogBase(root: string): void {
    if (root) logBase = root
}

/**
 * Sanitizes a filesystem path against an explicit base: under the base it is
 * written relative to it (the base itself as `.`), outside it stays absolute;
 * separators are normalized to `/`. Purely lexical — no filesystem access.
 * An already-relative input passes through normalized.
 */
export function logPathFor(base: string, path: string): string {
    const n = norm(path)
    if (!n || !base || !p.isAbsolute(n)) return n
    const rel = p.relative(base, n)
    if (rel === "") return "."
    if (rel.startsWith("..") || p.isAbsolute(rel)) return n
    return norm(rel)
}

/**
 * Sanitizes a filesystem path against the module-global base.
 *
 * @internal Standalone/test-only; instances call `ProjectContext.logPath`,
 * which binds the base to the owning root. Kept so the base policy can be
 * exercised in isolation.
 */
export function logPath(path: string): string {
    return logPathFor(logBase, path)
}

/** True when `n` is the given guard log or its `.1` rotation (case-insensitive). */
export function isGuardLogPathFor(logFile: string, raw: string): boolean {
    const log = norm(logFile)
    const n = norm(raw)
    if (!log || !n) return false
    const lower = n.toLowerCase()
    const base = log.toLowerCase()
    if (lower.endsWith(base) || lower.endsWith(`${base}.1`)) return true

    // Windows can represent the same path with a short (8.3) or long name.
    // Compare existing paths through the native resolver before deciding that
    // a link to the active log is unrelated.
    const native = (fsx.realpathSync as typeof fsx.realpathSync & { native?: (path: string) => string }).native
    const resolveExisting = (value: string): string => {
        try {
            return norm(native ? native(value) : fsx.realpathSync(value))
        } catch {
            return norm(value)
        }
    }
    const resolvedLog = resolveExisting(log)
    const resolved = resolveExisting(n)
    const resolvedLower = resolved.toLowerCase()
    const resolvedBase = resolvedLog.toLowerCase()
    return resolvedLower.endsWith(resolvedBase) || resolvedLower.endsWith(`${resolvedBase}.1`)
}

/**
 * Typed payload record per log event; `keyof LogPayload` is the closed event
 * registry. Payloads referencing filesystem paths carry the `logPath`-sanitized
 * value. `blocked.*` payloads stay open-ended (`alert()` fans them through
 * `sanitize()`); the discriminating fields are typed, extras allowed.
 */
export type FullRewriteReason =
    | "contains-secrets"
    | "not-file"
    | "too-large"
    | "metadata-failed"
    | "dangling-link"
    | "read-failed"

export type LogPayload = {
    loaded: { logSchema: number; pluginVersion: string; mode: string; directory: string; log: string }
    halted: { directory: string; log: string }
    "already-loaded": Record<never, never>
    "project-dir.ready": { root: string; log: string }
    "project-dir.failed": { step: string; error: string }
    "blacklist.loaded": { path: string; count: number; version: number }
    "blacklist.reloaded": { path: string; count: number; version: number; error?: string }
    "blacklist.invalid": { path: string; line: number; error: string }
    "redaction.failed": { at?: string; index?: number; tool?: string; error?: string }
    rehydrated: { tool: string; hashes: string[] }
    "rehydrated.external": { tool: string; files: string[] }
    summary: { blocks: number; counters: Record<string, number> }
    "redacted.prompt": RedactedRecord
    "redacted.history": RedactedRecord
    "redacted.system": RedactedRecord
    "redacted.tool": {
        tool: string
        sessionID?: unknown
        callID?: unknown
        unique: number
        total: number
        at: Record<string, number>
        patterns: string[]
    }
    "blocked.read": BlockedRecord
    "blocked.write": BlockedRecord
    "blocked.write.external": BlockedRecord
    "blocked.write.fullrewrite": BlockedRecord & { reason: FullRewriteReason }
    "blocked.marker-writeback": BlockedRecord
    "blocked.marker-inspection": BlockedRecord
    "blocked.bash.network": BlockedRecord
    "blocked.bash.path": BlockedRecord
    "blocked.bash.env": BlockedRecord
    "blocked.bash.secret": BlockedRecord
}

/** Shared payload of the `redacted.*` chat/history events. */
type RedactedRecord = { unique: number; total: number; patterns: string[] }

/** Open-ended payload of the `blocked.*` events (extras allowed, `alert()` fans them through `sanitize()`). */
type BlockedRecord = {
    sessionID?: unknown
    callID?: unknown
    tool?: string
    file?: string
    patterns?: string[]
    [k: string]: unknown
}

/** Numeric severity ranks; higher is more severe. */
const LEVEL_RANK: Record<string, number> = { debug: 0, info: 1, warn: 2, error: 3 }
const DEFAULT_LOG_RANK = 1
/** Minimum level emitted, from `SECURITY_GUARD_LOG_LEVEL` (default `info`). */
const MIN_LOG_RANK = LEVEL_RANK[(process.env.SECURITY_GUARD_LOG_LEVEL ?? "info").toLowerCase()] ?? DEFAULT_LOG_RANK

/** True when a record at `level` should be emitted. */
export const logAllows = (level: LogLevel): boolean => (LEVEL_RANK[level] ?? DEFAULT_LOG_RANK) >= MIN_LOG_RANK

/** Set once per sink, so a broken log file does not spam stderr on every event. */
const globalLogFailure = { warned: false }

/**
 * Append one JSON line to `logFile`, best-effort. Rotates to a single
 * `<logFile>.1` backup once the file exceeds `LOG_MAX`. Synchronous by design:
 * a dropped audit line is worse than a small blocking write. Never throws —
 * logging must not break the plugin — but warns once per sink on stderr if it
 * cannot.
 *
 * Typed boundary: `level` is the closed `LogLevel` union, `event` must be a
 * key of the `LogPayload` registry and `data` must match that event's payload —
 * required for events with fields, optional only for empty-payload events.
 * The record starts with the timestamp and level for readability. Controlled
 * fields are reapplied after `data` so it cannot spoof ts/level/event.
 */
export function writeLogToFile<E extends keyof LogPayload>(
    logFile: string,
    failure: { warned: boolean },
    level: LogLevel,
    event: E,
    data?: LogPayload[E],
): void {
    if (!logAllows(level)) return
    try {
        if (fsx.statSync(logFile).size > LOG_MAX) {
            const backup = `${logFile}.1`
            fsx.rmSync(backup, { force: true }) // rename does not overwrite on Windows
            fsx.renameSync(logFile, backup)
        }
    } catch {
        /* file does not exist yet, or rename failed — irrelevant */
    }
    try {
        const timestamp = new Date().toISOString()
        const record: Record<string, unknown> = { ts: timestamp, level, ...data, event }
        record.ts = timestamp
        record.level = level
        record.event = event
        fsx.appendFileSync(logFile, `${JSON.stringify(record)}\n`, "utf8")
    } catch {
        if (failure.warned) return
        failure.warned = true
        try {
            process.stderr.write("[security-guard] cannot write log file\n")
        } catch {
            /* stderr unavailable too — give up */
        }
    }
}

/** Events whose payload is empty; they are the only ones that may omit `data`. */
export type EmptyLogEvent = "already-loaded"

export function writeLog<E extends EmptyLogEvent>(level: LogLevel, event: E, data?: LogPayload[E]): void
export function writeLog<E extends Exclude<keyof LogPayload, EmptyLogEvent>>(
    level: LogLevel,
    event: E,
    data: LogPayload[E],
): void
export function writeLog<E extends keyof LogPayload>(level: LogLevel, event: E, data?: LogPayload[E]): void {
    writeLogToFile(LOG_FILE, globalLogFailure, level, event, data)
}

/** Instance log writer with the same typed boundary as `writeLog`. */
export interface ProjectLogWriter {
    <E extends EmptyLogEvent>(level: LogLevel, event: E, data?: LogPayload[E]): void
    <E extends Exclude<keyof LogPayload, EmptyLogEvent>>(level: LogLevel, event: E, data: LogPayload[E]): void
}

/**
 * Per-instance project runtime context: the resolved root, its captured log
 * destination, and bound logging operations. Hooks close over it instead of
 * the mutable module-level `LOG_FILE`/`logBase`.
 */
export interface ProjectContext {
    /** Resolved project root (worktree → directory → cwd). */
    readonly root: string
    /** Canonical root (links followed); `null` means it could not be inspected. */
    readonly canonicalRoot: string | null
    /** Active log path captured for this instance (mutable by relocation). */
    logFile: string
    /** Bound log writer for this instance's file. */
    readonly writeLog: ProjectLogWriter
    /** Path sanitizer against this instance's root. */
    readonly logPath: (path: string) => string
    /** Active-log match against this instance's file. */
    readonly isGuardLogPath: (path: string) => boolean
}

/** Creates a typed writer bound to a mutable instance sink. */
function createProjectWriter(getLogFile: () => string, failure: { warned: boolean }): ProjectLogWriter {
    return (<E extends keyof LogPayload>(level: LogLevel, event: E, data?: LogPayload[E]): void => {
        writeLogToFile(getLogFile(), failure, level, event, data)
    }) as ProjectLogWriter
}

/** Creates an instance context (best-effort parent directory, never throws). */
export function createProjectContext(opts: {
    root: string
    canonicalRoot?: string | null
    logFile: string
}): ProjectContext {
    try {
        fsx.mkdirSync(p.dirname(opts.logFile), { recursive: true })
    } catch {
        /* logging stays best-effort; the writer warns once instead */
    }
    const failure = { warned: false }
    const sink = { file: opts.logFile }
    const ctx: ProjectContext = {
        root: opts.root,
        canonicalRoot: opts.canonicalRoot === undefined ? opts.root : opts.canonicalRoot,
        get logFile() {
            return sink.file
        },
        set logFile(path: string) {
            sink.file = path
        },
        writeLog: createProjectWriter(() => sink.file, failure),
        logPath: (path: string): string => logPathFor(ctx.root, path),
        isGuardLogPath: (path: string): boolean => isGuardLogPathFor(ctx.logFile, path),
    }
    return ctx
}

/**
 * Relocates an instance log (project-local bootstrap). Best-effort: the parent
 * directory is created when possible; on failure the previous path is kept.
 */
export function setContextLogFile(ctx: ProjectContext, path: string): void {
    if (!path) return
    try {
        fsx.mkdirSync(p.dirname(path), { recursive: true })
    } catch {
        return
    }
    ctx.logFile = path
}

/**
 * Deterministic sibling for a colliding explicit log base: a pure function of
 * the canonical root, stable across restarts and computable by tests.
 */
export function siblingLogPath(base: string, canonicalRoot: string): string {
    const dir = p.dirname(base)
    const ext = p.extname(base)
    const stem = p.basename(base, ext)
    const suffix = createHash("sha256").update(canonicalRoot).digest("hex").slice(0, 16)
    return p.join(dir, `${stem}.${suffix}${ext}`)
}

/** Monotonic counter for the process-unique log fallback. */
let uniqueLogSeq = 0

/**
 * Collision-proof log fallback, used only when every bounded deterministic
 * salt is already owned. Uniqueness (not reproducibility) is the guarantee:
 * a process-unique token keeps concurrent instances from ever sharing a sink.
 */
export function uniqueSiblingLogPath(base: string): string {
    const dir = p.dirname(base)
    const ext = p.extname(base)
    const stem = p.basename(base, ext)
    const token = `${process.pid.toString(36)}-${(uniqueLogSeq++).toString(36)}-${randomBytes(4).toString("hex")}`
    return p.join(dir, `${stem}.${token}${ext}`)
}

/** Live instance registry: canonical identity key → captured context (discovery seam). */
const projectContexts = new Map<string, ProjectContext>()

/** Registers a context under its captured project identity key. */
export function registerProjectContext(identityKey: string, ctx: ProjectContext): void {
    projectContexts.set(identityKey, ctx)
}

/** Looks up the live context for an identity key, if any. */
export function getProjectContext(identityKey: string): ProjectContext | undefined {
    return projectContexts.get(identityKey)
}

/** Releases an identity key's context (dispose). */
export function releaseProjectContext(identityKey: string): void {
    projectContexts.delete(identityKey)
}

/** True when another live identity already owns `candidate` as its log file. */
export function isLogPathOwnedByOther(identityKey: string, candidate: string): boolean {
    const want = norm(p.resolve(candidate))
    for (const [otherIdentityKey, ctx] of projectContexts) {
        if (otherIdentityKey !== identityKey && norm(p.resolve(ctx.logFile)) === want) return true
    }
    return false
}
