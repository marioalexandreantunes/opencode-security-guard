/**
 * redact.ts — redaction helpers shared by the chat and tool hooks.
 * Redacts strings deeply, skipping structural identifiers, and fails closed
 * per string: a scanner error yields a placeholder, never the raw value.
 */
import { writeLog } from "./config.ts"
import { scan, type Hit } from "./rules.ts"

export const FAILED_PLACEHOLDER = "[security-guard] redaction failed"

export type ScanFn = (text: string) => { text: string; hits: Hit[] }

export type RedactOpts = {
    /** Scanner used per string; injectable so tests can force a failure. */
    scanFn?: ScanFn
    /** Hook label written to the log when a string fails to redact. */
    at?: string
}

/** Redact each string of an array, in place of the original array. */
export function redactStrings(strings: string[], hits: Hit[], opts: RedactOpts = {}): string[] {
    const scanFn = opts.scanFn ?? scan
    return strings.map((value, index) => {
        try {
            const result = scanFn(value)
            hits.push(...result.hits)
            return result.text
        } catch {
            const data: { at?: string; index: number } = { index }
            if (opts.at !== undefined) data.at = opts.at
            writeLog("error", "redaction.failed", data)
            return FAILED_PLACEHOLDER
        }
    })
}

/**
 * Redact every string of a value, deeply, guarding against cycles. Mirrors
 * `scanDeep` in rules.ts but fails closed per string: a scanner error yields a
 * placeholder instead of the raw value.
 */
export function redactDeep(value: unknown, hits: Hit[], seen = new WeakSet<object>(), opts: RedactOpts = {}): unknown {
    const scanFn = opts.scanFn ?? scan
    if (typeof value === "string") {
        try {
            const result = scanFn(value)
            hits.push(...result.hits)
            return result.text
        } catch {
            writeLog("error", "redaction.failed", opts.at === undefined ? {} : { at: opts.at })
            return FAILED_PLACEHOLDER
        }
    }
    if (value == null || typeof value !== "object") return value
    if (seen.has(value)) return value
    seen.add(value)
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) value[i] = redactDeep(value[i], hits, seen, opts)
        return value
    }
    const record = value as Record<string, unknown>
    for (const k of Object.keys(record)) record[k] = redactDeep(record[k], hits, seen, opts)
    return value
}

/** Redact the values of an object's own keys, skipping the listed keys. */
export function redactSkipping(obj: unknown, hits: Hit[], skip: ReadonlySet<string>, opts: RedactOpts = {}): void {
    if (!obj || typeof obj !== "object") return
    const record = obj as Record<string, unknown>
    const seen = new WeakSet<object>()
    for (const k of Object.keys(record)) {
        if (!skip.has(k)) record[k] = redactDeep(record[k], hits, seen, opts)
    }
}
