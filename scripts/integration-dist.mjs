// Dist-level integration harness: proves the packaged bundle protects every
// provider-bound surface. Run after `npm run build`:
//   npm run integration:dist
//
// It loads `dist/security-guard.js` (not `src/`), instantiates the plugin like
// a local opencode host would, and drives all provider-bound layers plus the
// tool boundary with synthetic canaries:
//
//   1. `chat.message` (Layer 3, prompt) — output `{ parts, message }`
//   2. `experimental.chat.messages.transform` (Layer 4, history) — multi-turn
//   3. `experimental.chat.system.transform` (Layer 5, system prompt)
//   4. `tool.execute.after` (Layer 2, tool output + metadata)
//   5. `tool.execute.before` with `bash` — a secret-bearing command MUST reject
//      (the plugin blocks by throwing, it never returns `{ block: true }`)
//   6. `tool.execute.before` with `bash` — a marker write-back MUST reject
//
// Pass criteria: no canary plaintext survives in any captured surface (string
// + JSON scan), every phase that carried a canary leaves a marker behind (so a
// canary the scanner would miss fails loudly instead of passing vacuously),
// and the isolated guard log carries the redaction audit trail with no
// plaintext. Any violation exits non-zero.
//
// Canaries are synthetic, opaque and assembled at runtime (never a full
// `key=value` literal in source, same convention as `smoke-dist.mjs`). Each
// phase carries its own canary, so "marker present + plaintext absent" on that
// phase proves that canary is detected by the scanner.
//
// NOTE on the log assertion: the guard log is hygiene-filtered by design —
// redaction events carry counts/patterns, never marker text (verified against
// the bundle: a redaction run leaves zero marker literals in the log). The
// harness therefore asserts per-canary markers on the captured surfaces (where
// attribution is exact) and asserts the log carries the redaction events with
// no canary plaintext (the audit trail without the leak channel).
import assert from "node:assert/strict"
import { existsSync, mkdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { cleanupIsolatedTestTmp, ensureIsolatedTestTmp } from "./test-tmp.mjs"

try {
    // Isolate the process temp directory BEFORE importing the bundle (config reads
    // SECURITY_GUARD_LOG at module load), so the harness never touches the user's
    // production log and leaves no temp artifacts behind. The project-local
    // bootstrap is disabled so the harness creates no `.security-guard/` in the
    // working directory.
    /** @type {string} */
    const root = ensureIsolatedTestTmp()
    /** @type {string} */
    const LOG = join(root, "guard.log")
    process.env.SECURITY_GUARD_LOG = LOG
    process.env.SECURITY_GUARD_PROJECT_DIR = "0"

    // Run from a fresh temp working directory (the repo checkout may already hold
    // a `.security-guard/` from the live plugin): this proves the harness itself
    // creates no project-local state where it runs.
    /** @type {string} */
    const workdir = join(root, "work")
    mkdirSync(workdir, { recursive: true })
    process.chdir(workdir)

    const mod = await import("../dist/security-guard.js")
    const exported = Object.keys(mod)
    if (exported.length !== 1 || exported[0] !== "SecurityGuard") {
        console.error(`integration-dist: expected a single export 'SecurityGuard', got: ${exported}`)
        process.exit(1)
    }

    const hooks = await mod.SecurityGuard({ client: {}, directory: process.cwd() })

    const chatMessageHook = hooks["chat.message"]
    const historyHook = hooks["experimental.chat.messages.transform"]
    const systemHook = hooks["experimental.chat.system.transform"]
    const beforeHook = hooks["tool.execute.before"]
    const afterHook = hooks["tool.execute.after"]
    if (typeof chatMessageHook !== "function") {
        console.error("integration-dist: hook 'chat.message' is missing (plugin halted or failed to register)")
        process.exit(1)
    }
    if (typeof historyHook !== "function") {
        console.error(
            "integration-dist: hook 'experimental.chat.messages.transform' is missing (plugin halted or failed to register)",
        )
        process.exit(1)
    }
    if (typeof systemHook !== "function") {
        console.error(
            "integration-dist: hook 'experimental.chat.system.transform' is missing (plugin halted or failed to register)",
        )
        process.exit(1)
    }
    if (typeof beforeHook !== "function") {
        console.error("integration-dist: hook 'tool.execute.before' is missing (plugin halted or failed to register)")
        process.exit(1)
    }
    if (typeof afterHook !== "function") {
        console.error("integration-dist: hook 'tool.execute.after' is missing (plugin halted or failed to register)")
        process.exit(1)
    }

    // ── Synthetic canaries (fragments only; assembled at runtime) ───────────────
    // A: bare-credential shape (prompt). B: bare-credential shape (history).
    // C: provider-token shape (system prompt + tool output).
    /** @type {string} */
    const FRAG_A = "Xy9kQ2mN7vR4tW8zB5c"
    /** @type {string} */
    const FRAG_B = "DedupFixtureA1b2C3d4E5"
    /** @type {string} */
    const FRAG_C = "Q7mK9vX2pL5nR8tW4zB6cD3eF"
    /** @type {string} */
    // biome-ignore lint/style/useTemplate: runtime-assembled canary — never a full key=value literal in source
    const CRED_A = "api_key=" + FRAG_A
    /** @type {string} */
    // biome-ignore lint/style/useTemplate: runtime-assembled canary — never a full key=value literal in source
    const CRED_B = "api_key=" + FRAG_B
    /** @type {string} */
    // biome-ignore lint/style/useTemplate: runtime-assembled canary — never a full key=value literal in source
    const CRED_C = "sk_live_" + FRAG_C
    /** @type {string[]} */
    const CANARIES = [FRAG_A, FRAG_B, FRAG_C, CRED_A, CRED_B, CRED_C]

    // Matches a redaction marker without naming its literal prefix.
    /** @type {RegExp} */
    const MARKER_RE = /<[A-Z_]+:[^:>]+:[0-9a-f]{16}>/g
    /** @type {RegExp} */
    const MARKER_HASH_RE = /<[A-Z_]+:[^:>]+:([0-9a-f]{16})>/g

    /**
     * Fail when any canary plaintext is present in `value` (raw + JSON scan).
     * @param {unknown} value
     * @param {string} surface
     */
    function assertNoLeak(value, surface) {
        const raw = String(value)
        const json = JSON.stringify(value) ?? ""
        for (const canary of CANARIES) {
            assert.ok(!raw.includes(canary), `${surface}: canary plaintext leaked (string scan)`)
            assert.ok(!json.includes(canary), `${surface}: canary plaintext leaked (JSON scan)`)
        }
    }

    /**
     * Return the marker identities found in `value`.
     * @param {unknown} value
     * @returns {Set<string>} the marker identities found
     */
    function markerHashes(value) {
        const text = JSON.stringify(value) ?? ""
        /** @type {Set<string>} */
        const hashes = new Set()
        for (const match of text.matchAll(MARKER_HASH_RE)) {
            if (match[1]) hashes.add(match[1])
        }
        return hashes
    }

    /**
     * Fail when `value` carries no redaction marker or misses an expected identity.
     * @param {unknown} value
     * @param {string} surface
     * @param {Set<string>} [expectedHashes]
     * @returns {Set<string>} the marker identities found
     */
    function assertMarked(value, surface, expectedHashes = new Set()) {
        const hashes = markerHashes(value)
        assert.ok(hashes.size > 0, `${surface}: no redaction marker — canary not detected?`)
        for (const hash of expectedHashes) {
            assert.ok(hashes.has(hash), `${surface}: missing marker identity for a canary`)
        }
        return hashes
    }

    /**
     * @typedef {import("@opencode-ai/plugin").Hooks} Hooks
     * @typedef {NonNullable<Hooks["chat.message"]>} ChatMessageHook
     * @typedef {NonNullable<Hooks["experimental.chat.messages.transform"]>} HistoryHook
     * @typedef {NonNullable<Hooks["experimental.chat.system.transform"]>} SystemHook
     * @typedef {NonNullable<Hooks["tool.execute.before"]>} BeforeHook
     * @typedef {NonNullable<Hooks["tool.execute.after"]>} AfterHook
     */

    /** Minimal model for the system-transform input (plugin ignores its content). */
    /** @type {import("@opencode-ai/sdk").Model} */
    const MODEL = {
        id: "integration-fixture",
        providerID: "fixture-provider",
        api: { id: "fixture-provider", url: "https://fixture.invalid", npm: "@fixture/provider" },
        name: "integration-fixture",
        capabilities: {
            temperature: true,
            reasoning: false,
            attachment: false,
            toolcall: false,
            input: { text: true, audio: false, image: false, video: false, pdf: false },
            output: { text: true, audio: false, image: false, video: false, pdf: false },
        },
        cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
        limit: { context: 4096, output: 1024 },
        status: "active",
        options: {},
        headers: {},
    }

    /** @type {Parameters<ChatMessageHook>[1]} */
    const chatOutput = {
        message: {
            id: "m-prompt",
            sessionID: "s-integration",
            role: "user",
            time: { created: 1 },
            agent: "build",
            model: { providerID: "fixture-provider", modelID: "integration-fixture" },
            system: CRED_A,
        },
        parts: [{ id: "p-prompt", sessionID: "s-integration", messageID: "m-prompt", type: "text", text: CRED_A }],
    }
    /** @type {Parameters<HistoryHook>[1]} */
    const historyOutput = {
        messages: [
            {
                info: {
                    id: "m-history",
                    sessionID: "s-integration",
                    role: "user",
                    time: { created: 1 },
                    agent: "build",
                    model: { providerID: "fixture-provider", modelID: "integration-fixture" },
                    system: CRED_B,
                },
                parts: [
                    {
                        id: "p-history",
                        sessionID: "s-integration",
                        messageID: "m-history",
                        type: "text",
                        text: CRED_B,
                    },
                ],
            },
            {
                info: {
                    id: "m-clean",
                    sessionID: "s-integration",
                    role: "assistant",
                    time: { created: 2, completed: 3 },
                    parentID: "m-history",
                    modelID: "integration-fixture",
                    providerID: "fixture-provider",
                    mode: "build",
                    path: { cwd: "/tmp", root: "/tmp" },
                    cost: 0,
                    tokens: { input: 1, output: 1, reasoning: 0, cache: { read: 0, write: 0 } },
                },
                parts: [
                    {
                        id: "p-clean",
                        sessionID: "s-integration",
                        messageID: "m-clean",
                        type: "text",
                        text: "nothing sensitive here",
                    },
                ],
            },
        ],
    }
    /** @type {string[]} */
    const systemArray = [CRED_C, "keep me"]
    /** @type {Parameters<SystemHook>[1]} */
    const systemOutput = { system: systemArray }
    /** @type {Parameters<AfterHook>[1]} */
    const toolOutput = {
        title: "fixture result",
        output: `deployed with ${CRED_A} and ${CRED_B}; token ${CRED_C}`,
        metadata: { note: CRED_A, nested: { token: CRED_C } },
    }

    // Layer 3 — prompt: canary A must not reach the provider.
    /** @type {Parameters<ChatMessageHook>[0]} */
    const chatInput = { sessionID: "s-integration" }
    await chatMessageHook(chatInput, chatOutput)
    assertNoLeak(chatOutput.parts, "chat.message parts")
    assertNoLeak(chatOutput.message, "chat.message message")
    const promptHashes = assertMarked(chatOutput, "chat.message")

    // Layer 4 — history: canary B in a prior turn must not reach the provider.
    /** @type {Parameters<HistoryHook>[0]} */
    const historyInput = {}
    await historyHook(historyInput, historyOutput)
    assertNoLeak(historyOutput.messages, "messages.transform")
    const historyHashes = assertMarked(historyOutput, "messages.transform")

    // Layer 5 — system prompt: canary C redacted in place (array identity kept).
    /** @type {Parameters<SystemHook>[0]} */
    const systemInput = { sessionID: "s-integration", model: MODEL }
    await systemHook(systemInput, systemOutput)
    assert.ok(systemOutput.system === systemArray, "system.transform must preserve the array identity")
    assert.equal(systemOutput.system[1], "keep me")
    assertNoLeak(systemOutput.system, "system.transform")
    const systemHashes = assertMarked(systemOutput, "system.transform")

    // Layer 2 — tool output: all three canaries redacted from output + metadata.
    /** @type {Parameters<AfterHook>[0]} */
    const toolInput = { tool: "bash", sessionID: "s-integration", callID: "c-integration", args: {} }
    await afterHook(toolInput, toolOutput)
    assertNoLeak(toolOutput, "tool.execute.after")
    assertMarked(toolOutput, "tool.execute.after", new Set([...promptHashes, ...historyHashes, ...systemHashes]))

    // Shell boundary — a secret-bearing bash command MUST reject. The plugin
    // blocks by throwing (it never returns `{ block: true }`).
    /** @type {Parameters<BeforeHook>[0]} */
    const shellInput = { tool: "bash", sessionID: "s-integration", callID: "c-shell" }
    /** @type {Parameters<BeforeHook>[1]} */
    // biome-ignore lint/style/useTemplate: runtime-assembled canary — never a full key=value literal in source
    const secretCall = { args: { command: "api_key=" + FRAG_A } }
    await assert.rejects(() => beforeHook(shellInput, secretCall), /secret in plain text/)

    // Shell boundary — a marker write-back MUST reject, so a marker never travels
    // back to a provider through the shell. The marker is taken from the redacted
    // prompt surface (never written as a literal).
    const promptMarkers = JSON.stringify(chatOutput).match(MARKER_RE) ?? []
    assert.ok(promptMarkers.length > 0, "shell probe: no marker available from the prompt surface")
    /** @type {Parameters<BeforeHook>[1]} */
    const writebackCall = { args: { command: `echo "${promptMarkers[0]}" > ${join(root, "leak.txt")}` } }
    await assert.rejects(() => beforeHook(shellInput, writebackCall), /marker/)

    // The three canary values (A, B, C) are distinct, so their idempotent markers
    // cannot collapse: the union of captured surfaces must carry one marker
    // identity per canary value.
    const unionText = JSON.stringify([chatOutput, historyOutput, systemOutput, toolOutput])
    const hashes = markerHashes(unionText)
    assert.ok(hashes.size >= 3, `expected one marker identity per canary value, got ${hashes.size}`)

    // Isolated log: the audit trail without the leak channel — redaction events
    // for every layer, and no canary plaintext anywhere.
    await hooks.dispose?.()
    const log = readFileSync(LOG, "utf8")
    for (const event of ["redacted.prompt", "redacted.history", "redacted.system", "redacted.tool"]) {
        assert.ok(log.includes(`"event":"${event}"`), `guard log: missing ${event} audit event`)
    }
    for (const canary of CANARIES) {
        assert.ok(!log.includes(canary), "guard log: canary plaintext leaked")
    }

    // Hermetic: no project-local state in the working directory.
    assert.ok(!existsSync(join(process.cwd(), ".security-guard")), "harness created .security-guard/ in cwd")

    console.log("integration-dist: OK")
} finally {
    cleanupIsolatedTestTmp()
}
