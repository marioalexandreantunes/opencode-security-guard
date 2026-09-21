/**
 * tool-output.ts — deep, fail-closed redaction of tool output values.
 */
import { scan, type Hit, type Scan } from "./rules.ts"
import { FAILED_PLACEHOLDER, type ScanFn } from "./redact.ts"

// Tool-output structural fields: never redacted when their value is primitive.
export const TOOL_SKIP = new Set(["id", "sessionID", "messageID", "callID", "time", "tokens", "cost", "type", "role"])

/** Traversal budgets for tool-output redaction; exceeding them fails closed. */
const TOOL_MAX_DEPTH = 64
const TOOL_MAX_NODES = 20000
const TOOL_MAX_STRING = 4 * 1024 * 1024

/** Injectable scanner (combined secrets + blacklist at the inference boundary). */
export type ToolRedactOpts = { scanFn?: ScanFn }

/**
 * Throwing deep redaction for tool output (does NOT catch per string, so the
 * caller's catch suppresses the whole output). Re-keys object keys that carry a
 * secret, keeps primitive structural fields, and enforces traversal budgets.
 */
export function redactToolValue(
    value: unknown,
    hits: Hit[],
    state: { nodes: number },
    opts: ToolRedactOpts = {},
    depth = 0,
    seen = new WeakSet<object>(),
): unknown {
    const scanFn: ScanFn = opts.scanFn ?? scan
    if (depth > TOOL_MAX_DEPTH) throw new Error("tool redaction: depth budget exceeded")
    if (++state.nodes > TOOL_MAX_NODES) throw new Error("tool redaction: node budget exceeded")
    if (typeof value === "string") {
        if (value.length > TOOL_MAX_STRING) throw new Error("tool redaction: string budget exceeded")
        const stringScan: Scan = scanFn(value)
        hits.push(...stringScan.hits)
        return stringScan.text
    }
    if (value == null || typeof value !== "object") return value
    if (seen.has(value)) return value
    seen.add(value)
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) value[i] = redactToolValue(value[i], hits, state, opts, depth + 1, seen)
        return value
    }
    const record = value as Record<string, unknown>
    for (const key of Object.keys(record)) {
        const v = record[key]
        if (TOOL_SKIP.has(key) && (v === null || typeof v !== "object")) continue
        const keyScan: Scan = scanFn(key)
        hits.push(...keyScan.hits)
        const redacted = redactToolValue(v, hits, state, opts, depth + 1, seen)
        if (keyScan.text !== key) {
            delete record[key]
            record[keyScan.text] = redacted
        } else {
            record[key] = redacted
        }
    }
    return value
}

/** Fail-closed: preserve the output shape but drop every string value. */
export function neutraliseOutput(output: Record<string, unknown>): void {
    const setData = (k: string, v: unknown): void => {
        try {
            output[k] = v
        } catch {
            // accessor-only property without a setter: force a data property
            Object.defineProperty(output, k, { value: v, enumerable: true, configurable: true, writable: true })
        }
    }
    for (const k of Object.keys(output)) {
        if (TOOL_SKIP.has(k)) continue
        let v: unknown
        try {
            v = output[k]
        } catch {
            v = FAILED_PLACEHOLDER // a throwing getter is treated as a leak
        }
        if (typeof v === "string") setData(k, FAILED_PLACEHOLDER)
        else if (Array.isArray(v)) setData(k, [])
        else if (v && typeof v === "object") setData(k, {})
    }
    setData("output", FAILED_PLACEHOLDER)
}
