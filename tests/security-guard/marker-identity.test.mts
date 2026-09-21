// Marker identity contract: opaque per-process fingerprints and their effect on
// redaction/rehydration. Synthetic values only.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/marker-identity.test.mts
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

process.env.SECURITY_GUARD_LOG = join(mkdtempSync(join(tmpdir(), "sg-marker-log-")), "guard.log")

const { createFingerprint, fp, MARKER } = await import("../../src/config.ts")
const { SecurityGuard } = await import("../../src/index.ts")

const HEX16 = /^[0-9a-f]{16}$/
const SYNTH = "Xy9kQ2mN7vR4tW8zB5c"
const mk = (rule: string, hash: string): string => `<${MARKER}:${rule}:${hash}>`

// ── pure derivation ───────────────────────────────────────────────────────
test("createFingerprint: 16 hex chars, stable per key, unlinkable across keys", () => {
    const a1 = createFingerprint("key-a", SYNTH)
    const a2 = createFingerprint("key-a", SYNTH)
    const b = createFingerprint("key-b", SYNTH)
    assert.match(a1, HEX16)
    assert.equal(a1, a2, "same key and value are deterministic")
    assert.notEqual(a1, b, "a different key yields an unlinkable identity")
})

test("fp: opaque 16-hex identity, stable within the process", () => {
    assert.match(fp(SYNTH), HEX16)
    assert.equal(fp(SYNTH), fp(SYNTH), "the same value reuses its identity")
    assert.notEqual(fp(SYNTH), fp(`${SYNTH}x`))
})

// ── integration through the real hooks ────────────────────────────────────
test("redaction mints a 16-char marker that rehydrates on write", async () => {
    const root = mkdtempSync(join(tmpdir(), "sg-marker-root-"))
    const hooks = await SecurityGuard({ client: {}, directory: root, worktree: root })
    const out: any = { output: `api_key=${SYNTH}`, metadata: {} }
    await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, out)
    const m = new RegExp(`<${MARKER}:[^:>]+:([0-9a-f]{16})>`).exec(String(out.output))
    assert.ok(m, `no marker minted: ${out.output}`)
    const args: any = { filePath: join(root, "out.txt"), content: `api_key=${m[0]}` }
    await hooks["tool.execute.before"]({ tool: "write" }, { args })
    assert.ok(args.content.includes(SYNTH), "the marker did not rehydrate")
    await hooks.dispose()
})

test("stale 10-char and absent 16-char markers both fail closed", async () => {
    const root = mkdtempSync(join(tmpdir(), "sg-marker-root2-"))
    const hooks = await SecurityGuard({ client: {}, directory: root, worktree: root })
    for (const hash of ["deadbeef00", "0123456789abcdef"]) {
        const args: any = { filePath: join(root, "out.txt"), content: `api_key=${mk("bare-credential", hash)}` }
        await assert.rejects(
            () => hooks["tool.execute.before"]({ tool: "write" }, { args }),
            /not in the vault/,
            `hash ${hash} must be treated as unknown`,
        )
    }
    await hooks.dispose()
})
