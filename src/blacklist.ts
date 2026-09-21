/**
 * blacklist.ts — team blacklist: a line-based denylist (literals, `#` comments,
 * `re:` patterns) matched case-insensitively at the inference boundary, with
 * mtime hot-reload and fail-open behavior. Internal deps: `config.ts` (fp,
 * writeLog, MARKER) and the `Hit`/`Scan` types from `rules.ts`.
 */
import * as fsx from "node:fs"
import { MARKER, fp, logPath, writeLog, type ProjectLogWriter } from "./config.ts"
import type { Hit, Scan } from "./rules.ts"

/** Logger injected by the owning instance; standalone use keeps the globals. */
export interface BlacklistLog {
    readonly writeLog: ProjectLogWriter
    readonly logPath: (path: string) => string
}

export type BlacklistOpts = {
    /** Blacklist file; `null`/empty disables matching (inert instance). */
    path?: string | null
    /** Poll interval in ms (`0` = every call, `-1` = never); default 2000/env. */
    ttlMs?: number
    /** Owning instance's logger (defaults to the module-global logger). */
    log?: BlacklistLog
}

export interface Blacklist {
    /** Re-reads the file when it changed; `true` when the terms were recompiled. */
    refresh(force?: boolean): boolean
    /** Redacts every blacklist term of a scan result, after the secret pass. */
    apply(input: Scan): Scan
    /** Drops every compiled term and disables further reloads. */
    clear(): void
    /** Number of compiled terms. */
    readonly size: number
}

type FileStat = { mtimeMs: number; size: number }

const DEFAULT_TTL_MS = 2000

/** Escape a literal so it compiles as a regex (kept local: module order). */
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

/** Spans that are already redacted; blacklist terms never re-match inside them. */
const MARKER_SPAN = new RegExp(`<${escapeRe(MARKER)}:[^:>]+:[0-9a-f]{16}>`, "g")

/** Poll TTL from `SECURITY_GUARD_BLACKLIST_TTL_MS`; invalid values use the default. */
function ttlFromEnv(): number {
    const raw = process.env.SECURITY_GUARD_BLACKLIST_TTL_MS
    if (raw === undefined || raw.trim() === "") return DEFAULT_TTL_MS
    const value = Number(raw)
    return Number.isFinite(value) ? value : DEFAULT_TTL_MS
}

/**
 * Parses the file into compiled matchers. Blank lines and `#` comments are
 * skipped; `re:` lines compile as case-insensitive regexes (an invalid one is
 * skipped and logged without the pattern); every other line is a literal.
 */
function parse(content: string, path: string, log: BlacklistLog): RegExp[] {
    const compiled: RegExp[] = []
    const lines = content.split(/\r?\n/)
    for (let index = 0; index < lines.length; index++) {
        const line = (lines[index] ?? "").trim()
        if (!line || line.startsWith("#")) continue
        if (line.startsWith("re:")) {
            const pattern = line.slice(3).trim()
            if (!pattern) {
                log.writeLog("warn", "blacklist.invalid", {
                    path: log.logPath(path),
                    line: index + 1,
                    error: "empty-pattern",
                })
                continue
            }
            try {
                compiled.push(new RegExp(pattern, "gi"))
            } catch {
                // Never log the pattern itself: it is blacklist content.
                log.writeLog("warn", "blacklist.invalid", {
                    path: log.logPath(path),
                    line: index + 1,
                    error: "invalid-regular-expression",
                })
            }
            continue
        }
        compiled.push(new RegExp(escapeRe(line), "gi"))
    }
    return compiled
}

/** Replaces one compiled pattern's matches in a span without marker text. */
function replaceSpan(span: string, regex: RegExp, hits: Hit[]): string {
    return span.replace(regex, (found: string) => {
        if (!found) return found // a regex may match the empty string
        const fingerprint = fp(found)
        hits.push({ rule: "blacklist", fp: fingerprint, value: found })
        return `<${MARKER}:blacklist:${fingerprint}>`
    })
}

/** Applies one compiled pattern outside every already-redacted `<MARKER:…>` span. */
function applyMatcher(text: string, regex: RegExp, hits: Hit[]): string {
    let out = ""
    let last = 0
    MARKER_SPAN.lastIndex = 0
    let match = MARKER_SPAN.exec(text)
    while (match !== null) {
        out += replaceSpan(text.slice(last, match.index), regex, hits) + match[0]
        last = match.index + match[0].length
        match = MARKER_SPAN.exec(text)
    }
    return out + replaceSpan(text.slice(last), regex, hits)
}

/**
 * Creates a blacklist instance. The file is loaded once at creation and then
 * hot-reloaded by mtime, subject to `ttlMs`. Every failure path is fail-open:
 * a missing file is an empty list, a read/parse failure keeps the previous
 * terms, and no call ever throws.
 */
export function createBlacklist(opts: BlacklistOpts = {}): Blacklist {
    const path = typeof opts.path === "string" && opts.path !== "" ? opts.path : null
    const ttlMs = opts.ttlMs ?? ttlFromEnv()
    const L: BlacklistLog = opts.log ?? { writeLog, logPath }
    let matchers: RegExp[] = []
    let version = 0
    let lastStat: FileStat | null = null
    let lastCheck = Date.now()
    let active = true

    const statOf = (): FileStat | null => {
        if (!path) return null
        try {
            const stat = fsx.statSync(path)
            return { mtimeMs: stat.mtimeMs, size: stat.size }
        } catch {
            return null
        }
    }
    const sameStat = (a: FileStat | null, b: FileStat | null): boolean =>
        a === b || (a !== null && b !== null && a.mtimeMs === b.mtimeMs && a.size === b.size)

    const load = (event: "blacklist.loaded" | "blacklist.reloaded"): boolean => {
        if (!path) return false
        let content: string
        try {
            content = fsx.readFileSync(path, "utf8")
        } catch (error) {
            if ((error as NodeJS.ErrnoException)?.code === "ENOENT") {
                // A missing file is an empty list, never an error.
                matchers = []
                lastStat = null
                L.writeLog("info", event, { path: L.logPath(path), count: 0, version })
                return false
            }
            L.writeLog("warn", "blacklist.reloaded", {
                path: L.logPath(path),
                count: matchers.length,
                version,
                error: "read-failed",
            })
            lastStat = statOf() // do not retry until the file changes again
            return false
        }
        matchers = parse(content, path, L)
        version++
        lastStat = statOf()
        L.writeLog("info", event, { path: L.logPath(path), count: matchers.length, version })
        return true
    }

    const refresh = (force = false): boolean => {
        if (!active || !path) return false
        if (!force) {
            if (ttlMs < 0) return false
            const now = Date.now()
            if (now - lastCheck < ttlMs) return false
            lastCheck = now
        } else {
            lastCheck = Date.now()
        }
        const current = statOf()
        if (sameStat(current, lastStat)) return false
        if (current === null) {
            // Deleted file: the list becomes empty (a missing file is no error).
            const had = matchers.length > 0
            matchers = []
            lastStat = null
            if (had) {
                version++
                L.writeLog("info", "blacklist.reloaded", { path: L.logPath(path), count: 0, version })
            }
            return had
        }
        return load("blacklist.reloaded")
    }

    const apply = (input: Scan): Scan => {
        if (!active || matchers.length === 0 || typeof input.text !== "string" || input.text === "") return input
        const hits: Hit[] = []
        let text = input.text
        for (const regex of matchers) text = applyMatcher(text, regex, hits)
        if (hits.length === 0) return input
        return { text, hits: [...input.hits, ...hits] }
    }

    const clear = (): void => {
        matchers = []
        active = false
    }

    load("blacklist.loaded")

    return {
        refresh,
        apply,
        clear,
        get size() {
            return matchers.length
        },
    }
}
