/**
 * plugin.ts — plugin factory: hooks, vault rehydration and log sanitization.
 * Bootstraps the project directory (`.security-guard/`), wires the combined
 * scanner (secrets + team blacklist) into every inference boundary and keeps
 * the blacklist hot-reloaded, invalidating the scan cache on change.
 */

import { existsSync } from "node:fs"
import * as p from "node:path"
import type { Hooks } from "@opencode-ai/plugin"
import {
    API_WRITE,
    ENV_DUMP,
    ENV_ECHO,
    ENV_EXPORT,
    MARKER_RE,
    NET_VERB,
    PS_ENV,
    sensitiveToken,
    WRITE_VERB,
} from "./bash.ts"
import { createBlacklist } from "./blacklist.ts"
import {
    createProjectContext,
    type FullRewriteReason,
    getProjectContext,
    isLogPathOwnedByOther,
    LOG_FILE,
    type LogPayload,
    logAllows,
    MARKER,
    MODE,
    norm,
    PLUGIN_VERSION,
    type ProjectContext,
    QUIET,
    registerProjectContext,
    releaseProjectContext,
    setContextLogFile,
    siblingLogPath,
    TOAST_COOLDOWN_MS,
    uniqueSiblingLogPath,
} from "./config.ts"
import { inspectDiskTarget, isSensitivePathFor, type SensitivityScope } from "./paths.ts"
import { bootstrapProjectDir, HALT_FILE, SECURITY_GUARD_DIR } from "./project-dir.ts"
import { redactSkipping, redactStrings } from "./redact.ts"
import { createScanCache, type Hit, rulesOf, SCAN_CACHE_MAX, type Scan, scan, uniqueOf } from "./rules.ts"
import { neutraliseOutput, redactToolValue, TOOL_SKIP } from "./tool-output.ts"
import { createVault } from "./vault.ts"
import { canonicalizeRoot, classifyDestination, resolveProjectRoot, writeTargets } from "./write-policy.ts"

/** Plugin log-schema revision; bump when the log record shape changes. */
const LOG_SCHEMA_VERSION = 12
/** Maximum deterministic collision salts for an already-occupied sibling. */
const MAX_LOG_COLLISION_ATTEMPTS = 16

/** Alert events: the blocked decisions plus the tool-output redaction report. */
type AlertEvent = Extract<keyof LogPayload, `blocked.${string}`> | "redacted.prompt" | "redacted.tool"
/** Novel-history redaction events (deduplicated by fingerprint). */
type RedactedEvent = "redacted.history" | "redacted.system"

// Structural fields that must never be redacted: identifiers, timestamps and
// token accounting are not secrets, and redacting them breaks the runtime.
const PART_SKIP = new Set(["id", "sessionID", "messageID", "type", "callID", "time", "tokens"])
const INFO_SKIP = new Set([
    "id",
    "sessionID",
    "parentID",
    "messageID",
    "modelID",
    "providerID",
    "agent",
    "role",
    "mode",
    "finish",
    "type",
    "callID",
    "time",
    "tokens",
    "cost",
])

/** Cap for the history-log dedup set, so it cannot grow unbounded per session. */
const SEEN_HISTORY_MAX = 5000

/** Insertion-ordered bounded set: evicts the oldest fingerprint past `max`. */
function createSeenSet(max: number): { has(fp: string): boolean; add(fp: string): void } {
    const seen = new Map<string, true>()
    return {
        has: (f) => seen.has(f),
        add: (f) => {
            if (seen.has(f)) seen.delete(f) // refresh LRU position
            seen.set(f, true)
            while (seen.size > max) {
                const oldest = seen.keys().next().value
                if (oldest === undefined) break
                seen.delete(oldest)
            }
        },
    }
}

/**
 * Fresh global regex capturing a marker's opaque identity. A new instance per
 * call keeps `lastIndex` independent between the inspection scan and the
 * rehydration replace, without duplicating the pattern literal.
 */
const markerCaptureRe = (): RegExp => new RegExp(`<${MARKER}:[^:>]+:([0-9a-f]{16})>`, "g")

type ChatMessageHook = NonNullable<Hooks["chat.message"]>
type MessagesTransformHook = NonNullable<Hooks["experimental.chat.messages.transform"]>
type SystemTransformHook = NonNullable<Hooks["experimental.chat.system.transform"]>
type ToolBeforeHook = NonNullable<Hooks["tool.execute.before"]>
type ToolAfterHook = NonNullable<Hooks["tool.execute.after"]>
type ToolBeforeInput = Parameters<ToolBeforeHook>[0]
type ToolBeforeOutput = Parameters<ToolBeforeHook>[1]
type ToolAfterInput = Parameters<ToolAfterHook>[0]
// Tool output is a generic bag: the guard redacts every own field, including
// ones the SDK does not declare, so it is also viewed as a string-keyed record.
type ToolAfterOutput = Parameters<ToolAfterHook>[1] & Record<string, unknown>

/** Minimal opencode client surface used by the guard (best-effort log + toast). */
type GuardClient = {
    app?: { log?: (input: { body: Record<string, unknown> }) => Promise<unknown> }
    tui?: { showToast?: (input: unknown) => Promise<unknown> }
}
type SecurityGuardInput = { client?: GuardClient; directory?: unknown; worktree?: unknown }

/**
 * opencode plugin factory. Registers the five guard layers (README §layers) and
 * returns the hook map. Registration is idempotent per resolved project root:
 * a second call for the same root (the plugin installed both globally and in
 * the project) logs `already-loaded` and returns `{}`, a different root
 * registers its own hooks, and `dispose` releases the root so a later load
 * (hot reload / re-init) registers again.
 */
export const SecurityGuard = async ({ client, directory, worktree }: SecurityGuardInput) => {
    const projectRoot = resolveProjectRoot(worktree, directory)

    // Keep duplicate factory calls side-effect free: the owner (if any) logs
    // already-loaded to its own context before any other work runs.
    const owner = getProjectContext(projectRoot)
    if (owner) {
        owner.writeLog("info", "already-loaded")
        return {}
    }

    const canonicalRoot = canonicalizeRoot(projectRoot)

    // Project-local state (`.security-guard/`): bootstrap on by default, disabled
    // with SECURITY_GUARD_PROJECT_DIR=0. An explicit SECURITY_GUARD_BLACKLIST
    // wins even when the bootstrap is disabled.
    const projectDirOn = (process.env.SECURITY_GUARD_PROJECT_DIR ?? "1") !== "0"

    // Instance log destination: the explicit override, else the project-local
    // log, else the process default. A destination already owned by another
    // live root gets a deterministic sibling — instance logs are never shared.
    const explicitLog = process.env.SECURITY_GUARD_LOG
    const baseLog =
        explicitLog && explicitLog.trim() !== ""
            ? explicitLog
            : projectDirOn
              ? p.join(projectRoot, SECURITY_GUARD_DIR, "security-guard.log")
              : LOG_FILE
    const instance: ProjectContext = createProjectContext({ root: projectRoot, canonicalRoot, logFile: baseLog })
    if (isLogPathOwnedByOther(projectRoot, instance.logFile)) {
        // Deterministic per (base, root, salt): try bounded salts first, so
        // the common multi-root case stays reproducible. If even those are
        // taken, a process-unique fallback guarantees the sink is never shared.
        const logIdentityRoot = canonicalRoot ?? projectRoot
        let sibling = siblingLogPath(baseLog, logIdentityRoot)
        for (let n = 1; isLogPathOwnedByOther(projectRoot, sibling) && n <= MAX_LOG_COLLISION_ATTEMPTS; n++) {
            sibling = siblingLogPath(baseLog, `${logIdentityRoot}#${n}`)
        }
        if (isLogPathOwnedByOther(projectRoot, sibling)) sibling = uniqueSiblingLogPath(baseLog)
        setContextLogFile(instance, sibling)
    }

    if (projectDirOn) {
        bootstrapProjectDir(projectRoot, {
            log: {
                get file() {
                    return instance.logFile
                },
                setFile: (path: string) => setContextLogFile(instance, path),
                writeLog: instance.writeLog,
                logPath: instance.logPath,
            },
        })
    }

    // Kill switch: `<projectRoot>/.security-guard/halt` (the git worktree, or
    // the opencode directory when there is no worktree) disables the guard for
    // this project before it can register hooks.
    if (projectDirOn && existsSync(p.join(projectRoot, SECURITY_GUARD_DIR, HALT_FILE))) {
        instance.writeLog("info", "halted", {
            directory: instance.logPath(norm(projectRoot)),
            log: instance.logPath(instance.logFile),
        })
        return {}
    }

    registerProjectContext(instance)

    const explicitBlacklist = process.env.SECURITY_GUARD_BLACKLIST
    const blacklist = createBlacklist({
        path: explicitBlacklist || (projectDirOn ? p.join(projectRoot, ".security-guard", "blacklist") : null),
        log: { writeLog: instance.writeLog, logPath: instance.logPath },
    })

    const counters = new Map<string, number>()
    const seenHistory = createSeenSet(SEEN_HISTORY_MAX) // avoids one history log per turn
    let blocks = 0
    let lastToast = 0

    const vault = createVault()
    const combinedScan = (text: string): Scan => blacklist.apply(scan(text))
    const scanCache = createScanCache(SCAN_CACHE_MAX, combinedScan)

    /**
     * Reload hook entry point: a blacklist change invalidates the negative scan
     * cache, because a string cached as clean may now contain a team term.
     */
    const refreshBlacklist = (): void => {
        if (blacklist.refresh()) scanCache.clear()
    }

    // Flags are read at call time so tests (and runtime) can toggle them.
    const rehydrateOn = (): boolean => (process.env.SECURITY_GUARD_REHYDRATE ?? "1") !== "0"
    const rehydrateBashOn = (): boolean => process.env.SECURITY_GUARD_REHYDRATE_BASH === "1"
    const rehydrateExternalOn = (): boolean => process.env.SECURITY_GUARD_REHYDRATE_EXTERNAL === "1"

    // `<MARKER:rule:hash>` — dedicated capture; the shared MARKER_RE is global
    // and does not capture the hash.
    const REHYDRATE_RE = markerCaptureRe()

    /** Scope for the instance-aware sensitive-path check (log file read live). */
    const sensitivityScope = (): SensitivityScope => ({
        logFile: instance.logFile,
        root: instance.root,
        canonicalRoot: instance.canonicalRoot,
    })

    type RehydrateAcc = { known: number; hashes: string[] }

    /** Remember every redacted value so it can be restored before execution. */
    function remember(hits: Hit[]): void {
        for (const h of hits) if (h.value) vault.store(h.fp, h.value)
    }

    /** Guarded marker inspection of write arguments (serializes exactly once). */
    function inspectArgs(args: unknown): {
        status: "clean" | "known" | "unknown" | "uninspectable"
        text: string
    } {
        let text: string
        try {
            const serialized = JSON.stringify(args)
            text = typeof serialized === "string" ? serialized : ""
        } catch {
            return { status: "uninspectable", text: "" }
        }
        if (!text.includes(MARKER)) return { status: "clean", text }
        const re = markerCaptureRe()
        let match: RegExpExecArray | null
        // biome-ignore lint/suspicious/noAssignInExpressions: canonical regex exec loop
        while ((match = re.exec(text))) {
            const hash = match[1]
            if (hash !== undefined && vault.lookup(hash) !== undefined) return { status: "known", text }
        }
        return { status: "unknown", text }
    }

    /**
     * Rejects a write whose arguments cannot be inspected for markers. The
     * diagnostic carries a stable code only — never argument content, marker
     * text, or engine messages.
     */
    async function blockUninspectable(
        correlation: { sessionID?: unknown; callID?: unknown },
        tool: string,
    ): Promise<never> {
        await alert(
            "blocked.marker-inspection",
            { ...correlation, tool, error: "marker-inspection-failed" },
            "Blocked: cannot inspect content for markers",
        )
        throw new Error(
            `security-guard: ${tool} blocked — the arguments could not be inspected for markers, ` +
                `so the write was rejected. Retry with plain JSON content.`,
        )
    }

    /** Replace known markers with their real values, deeply. */
    function rehydrateDeep(value: unknown, restored: RehydrateAcc, seen = new WeakSet<object>()): unknown {
        if (typeof value === "string") {
            return value.replace(REHYDRATE_RE, (match: string, hash: string) => {
                const real = vault.lookup(hash)
                if (real === undefined) return match
                restored.known++
                restored.hashes.push(hash)
                return real
            })
        }
        if (value == null || typeof value !== "object") return value
        if (seen.has(value)) return value
        seen.add(value)
        if (Array.isArray(value)) {
            for (let i = 0; i < value.length; i++) value[i] = rehydrateDeep(value[i], restored, seen)
            return value
        }
        const record = value as Record<string, unknown>
        for (const k of Object.keys(record)) record[k] = rehydrateDeep(record[k], restored, seen)
        return value
    }

    /** Increment the per-rule counters, one per distinct rule per event. */
    function bump(patterns: string[]): void {
        for (const pattern of patterns) counters.set(pattern, (counters.get(pattern) ?? 0) + 1)
    }

    /**
     * Log a redaction event for fingerprints not seen this session, bumping the
     * counters only for the novel ones. Shared by the message and system hooks.
     */
    function reportNovelHistory(hits: Hit[], event: RedactedEvent): void {
        const novel = hits.filter((h) => !seenHistory.has(h.fp))
        for (const h of hits) seenHistory.add(h.fp)
        if (!novel.length) return
        const patterns = rulesOf(novel)
        bump(patterns) // keep the dispose summary accurate
        instance.writeLog("info", event, {
            unique: uniqueOf(novel),
            total: novel.length,
            patterns,
        })
    }

    /**
     * Redact every string of a log payload with the combined scanner,
     * preserving the typed payload shape (D6): the event keys the generic, so
     * the record reaches `writeLog` still typed, with no weakening cast.
     */
    const sanitize = <E extends keyof LogPayload>(_event: E, data: LogPayload[E]): LogPayload[E] => {
        try {
            return JSON.parse(JSON.stringify(data, (_k, v) => (typeof v === "string" ? combinedScan(v).text : v)))
        } catch {
            // Unreachable for the plain-object payloads built at the call sites.
            return { _sanitizeError: true } as unknown as LogPayload[E]
        }
    }

    async function alert<E extends AlertEvent>(event: E, data: LogPayload[E], toast: string): Promise<void> {
        const safe = sanitize(event, data)
        // Blocked events are warnings; plain redactions are informational.
        const blocked = event.startsWith("blocked.")
        instance.writeLog(blocked ? "warn" : "info", event, safe)
        bump(data.patterns ?? [])
        if (blocked) blocks++

        if (logAllows(blocked ? "warn" : "info")) {
            try {
                await client?.app?.log?.({
                    body: { service: "security-guard", level: blocked ? "warn" : "info", message: toast, extra: safe },
                })
            } catch {
                /* the file is the source of truth */
            }
        }

        if (QUIET || Date.now() - lastToast < TOAST_COOLDOWN_MS) return
        lastToast = Date.now()

        const show = client?.tui?.showToast
        if (!show) return
        // SDK v1: { body: {...} } | SDK v2: flat. `.call` keeps the receiver
        // (showToast uses this._client; a detached call threw TypeError).
        try {
            await show.call(client.tui, { body: { title: "security-guard", message: toast, variant: "warning" } })
        } catch {
            try {
                await show.call(client.tui, { title: "security-guard", message: toast, variant: "warning" })
            } catch {
                /* toast is best-effort */
            }
        }
    }

    instance.writeLog("info", "loaded", {
        logSchema: LOG_SCHEMA_VERSION,
        pluginVersion: PLUGIN_VERSION,
        mode: MODE,
        directory: instance.logPath(norm(directory)),
        log: instance.logPath(instance.logFile),
    })

    const chatMessage: ChatMessageHook = async (_input, output) => {
        refreshBlacklist()
        const hits: Hit[] = []
        for (const part of output?.parts ?? [])
            redactSkipping(part, hits, PART_SKIP, { at: "chat.message", scanFn: scanCache.scan })
        if (output?.message)
            redactSkipping(output.message, hits, INFO_SKIP, { at: "chat.message", scanFn: scanCache.scan })
        remember(hits)
        if (hits.length) {
            const patterns = rulesOf(hits)
            await alert(
                "redacted.prompt",
                { unique: uniqueOf(hits), total: hits.length, patterns },
                `Secret(s) removed from your prompt: ${patterns.join(", ")}`,
            )
        }
    }

    const messagesTransform: MessagesTransformHook = async (_input, output) => {
        refreshBlacklist()
        const hits: Hit[] = []
        for (const message of output?.messages ?? []) {
            for (const part of message?.parts ?? [])
                redactSkipping(part, hits, PART_SKIP, { at: "messages.transform", scanFn: scanCache.scan })
            if (message?.info)
                redactSkipping(message.info, hits, INFO_SKIP, { at: "messages.transform", scanFn: scanCache.scan })
        }
        remember(hits)
        reportNovelHistory(hits, "redacted.history")
    }

    const systemTransform: SystemTransformHook = async (_input, output) => {
        refreshBlacklist()
        const hits: Hit[] = []
        const redacted = redactStrings(output.system ?? [], hits, { at: "system.transform", scanFn: scanCache.scan })
        // C1: mutate the existing array in place so its identity is preserved.
        if (Array.isArray(output.system)) {
            output.system.splice(0, output.system.length, ...redacted)
        } else {
            output.system = redacted
        }
        remember(hits)
        reportNovelHistory(hits, "redacted.system")
    }

    return {
        // ─────────────────────────────────────────────────────────────────────
        // Layer 1 — block before execution
        // ─────────────────────────────────────────────────────────────────────
        "tool.execute.before": async (input: ToolBeforeInput, output: ToolBeforeOutput) => {
            refreshBlacklist()
            const tool = String(input?.tool ?? "")
            const args = output?.args ?? {}
            // Correlate every block with the originating session/call.
            const ctx = { sessionID: input?.sessionID, callID: input?.callID }

            // sensitive file read (only in MODE=block; in redact it reads and redacts)
            const fileTool =
                tool === "read" || tool === "write" || tool === "edit" || tool === "patch" || tool === "apply_patch"
            const inspectedArgs = fileTool ? inspectArgs(args) : null
            const inspection = inspectedArgs ?? { status: "clean" as const, text: "" }
            if (inspection.status === "uninspectable") {
                await blockUninspectable(ctx, tool)
            }

            let readPath: unknown = ""
            if (tool === "read") {
                try {
                    readPath = args.filePath ?? ""
                } catch {
                    await blockUninspectable(ctx, tool)
                }
            }
            if (tool === "read" && MODE === "block" && isSensitivePathFor(sensitivityScope(), readPath)) {
                const file = instance.logPath(norm(readPath))
                await alert("blocked.read", { ...ctx, tool, file }, `Read blocked: ${file}`)
                throw new Error(`security-guard: read blocked — "${file}" is a sensitive file.`)
            }

            // write / edit
            let targets: string[] = []
            if (tool === "write" || tool === "edit" || tool === "patch" || tool === "apply_patch") {
                // Getters can still throw after JSON inspection (for example a
                // non-enumerable or stateful getter), so target extraction is a
                // second guarded boundary rather than an assumed-safe read.
                try {
                    targets = writeTargets(args)
                } catch {
                    await blockUninspectable(ctx, tool)
                }

                // sensitive paths are blocked before any secret is restored
                for (const t of targets) {
                    if (isSensitivePathFor(sensitivityScope(), t)) {
                        const file = instance.logPath(t)
                        await alert("blocked.write", { ...ctx, tool, file }, `${tool} blocked: ${file}`)
                        throw new Error(`security-guard: ${tool} blocked — "${file}" is a sensitive file.`)
                    }
                }

                // Marker inspection runs before rehydration and fails closed:
                // uninspectable arguments reject with a stable coded block.
                // Rehydration: restore known markers; any marker left = block.
                if (rehydrateOn()) {
                    // C2: a known marker may only be materialised inside the worktree.
                    const known = inspection.status === "known"
                    const outside = targets.filter(
                        (t) => classifyDestination(projectRoot, t, instance.canonicalRoot).verdict !== "inside",
                    )
                    const firstOutside = outside[0]
                    if (known && firstOutside !== undefined && !rehydrateExternalOn()) {
                        const file = instance.logPath(firstOutside)
                        await alert(
                            "blocked.write.external",
                            { ...ctx, tool, file },
                            `Blocked: rehydrated secret outside the project (${file})`,
                        )
                        throw new Error(
                            `security-guard: ${tool} blocked — it would write a rehydrated secret outside the ` +
                                `project worktree ("${file}"). Set SECURITY_GUARD_REHYDRATE_EXTERNAL=1 to allow it.`,
                        )
                    }

                    const restored: RehydrateAcc = { known: 0, hashes: [] }
                    try {
                        rehydrateDeep(args, restored)
                    } catch {
                        await blockUninspectable(ctx, tool)
                    }
                    if (known && outside.length && restored.known) {
                        instance.writeLog("warn", "rehydrated.external", {
                            tool,
                            files: outside.map((target) => instance.logPath(target)),
                        })
                    }
                    let remainder = ""
                    try {
                        remainder = JSON.stringify(args) ?? ""
                    } catch {
                        await blockUninspectable(ctx, tool)
                    }
                    if (remainder.includes(MARKER)) {
                        await alert(
                            "blocked.marker-writeback",
                            { ...ctx, tool },
                            "Blocked: unknown marker — cannot restore the real value",
                        )
                        throw new Error(
                            `security-guard: ${tool} blocked — the content contains a marker that is not in the ` +
                                `vault (unknown or evicted), so it cannot be restored. Writing it would corrupt the file.`,
                        )
                    }
                    if (restored.known) instance.writeLog("info", "rehydrated", { tool, hashes: restored.hashes })
                } else if (inspection.text.includes(MARKER)) {
                    await alert(
                        "blocked.marker-writeback",
                        { ...ctx, tool },
                        "Blocked: attempt to write redacted content to a file",
                    )
                    throw new Error(
                        `security-guard: ${tool} blocked — the content contains ${MARKER} markers, ` +
                            `which are placeholders, not the real values. Use "edit" with surgical changes ` +
                            `outside the redacted lines instead of rewriting the file.`,
                    )
                }
            }

            // Full rewrite of a file that contains secrets: the agent NEVER saw
            // the real values, so it cannot reproduce the file faithfully.
            // Only `edit` is safe. Reuse the guarded target so stateful getters
            // are never read again, and resolve relative targets to this root.
            if (tool === "write") {
                const target = targets[0]
                if (!rehydrateOn() && target !== undefined) {
                    const resolvedTarget = p.resolve(projectRoot, target)
                    const result = inspectDiskTarget(resolvedTarget)
                    if (result.status !== "missing" && result.status !== "clean") {
                        const reason: FullRewriteReason =
                            result.status === "unverifiable" ? result.reason : "contains-secrets"
                        const file = instance.logPath(target)
                        await alert(
                            "blocked.write.fullrewrite",
                            { ...ctx, tool, file, reason },
                            result.status === "contains-secrets"
                                ? `write blocked: ${file} contains redacted secrets`
                                : `write blocked: ${file} could not be inspected safely (${reason})`,
                        )
                        if (result.status === "contains-secrets") {
                            throw new Error(
                                `security-guard: write blocked — "${file}" contains secrets that were ` +
                                    `redacted from you, so you cannot reproduce the file faithfully. ` +
                                    `Use "edit" with oldString/newString for surgical changes.`,
                            )
                        }
                        throw new Error(
                            `security-guard: write blocked — "${file}" could not be inspected safely ` +
                                `(${reason}), so an existing target cannot be overwritten. ` +
                                `Use "edit" with oldString/newString for surgical changes.`,
                        )
                    }
                }
            }

            // bash
            if (tool === "bash") {
                const cmd = String(args.command ?? "")

                // a marker next to a network verb is an exfiltration attempt
                if (cmd.includes(MARKER) && NET_VERB.test(cmd)) {
                    await alert(
                        "blocked.bash.network",
                        { ...ctx, tool: "bash" },
                        "Blocked: network command with a redacted marker",
                    )
                    throw new Error(
                        `security-guard: command blocked [exfiltration] — a redacted marker next to a ` +
                            `network command (curl/wget/ssh/…) looks like exfiltration.`,
                    )
                }

                // markers must not reach disk — not via write/edit, not via shell.
                // (echo to stdout is still allowed: it writes nothing)
                const inline = cmd.replace(MARKER_RE, "«M»")
                if (!rehydrateBashOn() && cmd.includes(MARKER) && (WRITE_VERB.test(inline) || API_WRITE.test(inline))) {
                    await alert(
                        "blocked.marker-writeback",
                        { ...ctx, tool: "bash" },
                        "Blocked: attempt to write redacted content via the shell",
                    )
                    throw new Error(
                        `security-guard: command blocked — it contains ${MARKER} markers in a write ` +
                            `operation. They are placeholders, not the real values; writing them corrupts the file.`,
                    )
                }

                const target = sensitiveToken(cmd)
                if (target) {
                    const file = instance.logPath(target)
                    await alert("blocked.bash.path", { ...ctx, file }, `Command blocked (${file})`)
                    throw new Error(
                        `security-guard: command blocked [sensitive file] — it references the sensitive ` +
                            `file "${file}".`,
                    )
                }

                if (ENV_DUMP.test(cmd) || PS_ENV.test(cmd) || ENV_ECHO.test(cmd) || ENV_EXPORT.test(cmd)) {
                    await alert("blocked.bash.env", { ...ctx, tool: "bash" }, "Command blocked: environment dump")
                    throw new Error(
                        `security-guard: command blocked [environment/variable dump] — listing or ` +
                            `printing environment variables can expose secrets.`,
                    )
                }

                // anti-exfiltration: a secret in plain text inside the command
                const commandScan = scan(cmd)
                if (commandScan.hits.length) {
                    const patterns = rulesOf(commandScan.hits)
                    await alert(
                        "blocked.bash.secret",
                        { ...ctx, patterns },
                        `Command blocked: it contains a secret (${patterns.join(", ")})`,
                    )
                    throw new Error(
                        `security-guard: command blocked [secret in plain text] — it contains a secret ` +
                            `in plain text (${patterns.join(", ")}). Pass it through an environment variable instead.`,
                    )
                }

                // Rehydrate known markers for local commands (opt-in).
                if (rehydrateBashOn()) {
                    const restored: RehydrateAcc = { known: 0, hashes: [] }
                    rehydrateDeep(args, restored)
                    if (String(args.command ?? "").includes(MARKER)) {
                        await alert(
                            "blocked.marker-writeback",
                            { ...ctx, tool: "bash" },
                            "Blocked: unknown marker in command",
                        )
                        throw new Error(`security-guard: command blocked — it contains a marker not in the vault.`)
                    }
                    if (restored.known)
                        instance.writeLog("info", "rehydrated", { tool: "bash", hashes: restored.hashes })
                }
            }
        },

        // ─────────────────────────────────────────────────────────────────────
        // Layer 2 — redact after execution: ALL tools, all fields
        // ─────────────────────────────────────────────────────────────────────
        "tool.execute.after": async (input: ToolAfterInput, output: ToolAfterOutput) => {
            if (!output) return
            refreshBlacklist()
            const tool = String(input?.tool ?? "")

            try {
                const at: Record<string, number> = {}
                const all: Hit[] = []
                const state = { nodes: 0 }

                // C3: redact every own string-bearing field, recursively.
                // Structural identifiers at the top level are preserved.
                for (const k of Object.keys(output)) {
                    if (TOOL_SKIP.has(k)) continue
                    const h: Hit[] = []
                    output[k] = redactToolValue(output[k], h, state, { scanFn: combinedScan })
                    if (h.length) at[k] = (at[k] ?? 0) + h.length
                    all.push(...h)
                }

                remember(all)

                if (all.length) {
                    const patterns = rulesOf(all)
                    const unique = uniqueOf(all)
                    await alert(
                        "redacted.tool",
                        {
                            tool,
                            sessionID: input?.sessionID,
                            callID: input?.callID,
                            unique, // distinct secrets (by fingerprint)
                            total: all.length, // occurrences, incl. copies in metadata
                            at, // where they were found
                            patterns,
                        },
                        `${unique} secret(s) redacted in "${tool}" (${patterns.join(", ")})`,
                    )
                }
            } catch {
                // fail-closed: suppress the whole output, preserving its shape
                instance.writeLog(
                    "error",
                    "redaction.failed",
                    sanitize("redaction.failed", { tool, error: "redaction-error" }),
                )
                neutraliseOutput(output)
            }
        },

        // ─────────────────────────────────────────────────────────────────────
        // Layer 3 — your prompt, before it leaves to the provider
        // ─────────────────────────────────────────────────────────────────────
        "chat.message": chatMessage,

        // ─────────────────────────────────────────────────────────────────────
        // Layer 4 — last line of defence: the full history sent to inference.
        //     Redaction always runs; only the log is deduplicated by fingerprint.
        // ─────────────────────────────────────────────────────────────────────
        "experimental.chat.messages.transform": messagesTransform,

        // ─────────────────────────────────────────────────────────────────────
        // Layer 5 — system prompt, before it leaves to the provider.
        // ─────────────────────────────────────────────────────────────────────
        "experimental.chat.system.transform": systemTransform,

        dispose: async () => {
            vault.clear()
            blacklist.clear()
            scanCache.clear()
            releaseProjectContext(projectRoot)
            if (counters.size || blocks) {
                instance.writeLog("info", "summary", { blocks, counters: Object.fromEntries(counters) })
            }
        },
    }
}
