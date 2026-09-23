// security-guard scan-cache suite (memoize-history-scan).
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/scan-cache.test.mts

import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { createBlacklist } from "../../src/blacklist.ts"
import { loadFactory, loadGuard } from "./extract.mts"

const g: Record<string, any> = await loadGuard()
const { scan, createScanCache, SCAN_CACHE_MAX, MARKER } = g

const mk = (rule: string, hash = "0123456789abcdef"): string => `<${MARKER}:${rule}:${hash}>`
const CLEAN = "just an ordinary line of text"
const SECRET = "ghp_" + "oNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzA"

/** Wraps a scanner and counts how many times the cache calls it. */
function counting(scanner: (t: string) => any = scan) {
    let calls = 0
    const fn = (text: string) => {
        calls++
        return scanner(text)
    }
    return { fn, calls: () => calls }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3.1 — negative-only memoization
test("scan-cache: a clean string is scanned once", () => {
    const { fn, calls } = counting()
    const cache = createScanCache(10, fn)
    const a = cache.scan(CLEAN)
    const b = cache.scan(CLEAN)
    assert.equal(calls(), 1, "underlying scanner should run once")
    assert.deepEqual(a, b)
    assert.equal(a.text, CLEAN)
    assert.deepEqual(a.hits, [])
})

test("scan-cache: a secret string is never cached", () => {
    const { fn, calls } = counting()
    const cache = createScanCache(10, fn)
    const a = cache.scan(SECRET)
    assert.equal(cache.size, 0, "a positive result must not create an entry")
    const b = cache.scan(SECRET)
    assert.equal(calls(), 2, "the scanner must run again")
    assert.ok(a.hits.length > 0 && b.hits.length > 0)
    assert.equal(cache.size, 0)
})

test("scan-cache: cached and uncached results match", () => {
    const cache = createScanCache(100)
    const inputs = [CLEAN, SECRET, mk("jwt"), "", "ls -la", "grep TODO src/"]
    for (const s of inputs) {
        const direct = scan(s)
        const cached = cache.scan(s)
        assert.equal(cached.text, direct.text, `text parity: ${s}`)
        assert.deepEqual(
            cached.hits.map((h: any) => h.fp),
            direct.hits.map((h: any) => h.fp),
            `hit parity: ${s}`,
        )
    }
})

test("scan-cache: cached and uncached combined results match", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sg-scan-combined-")), "blacklist")
    writeFileSync(path, "ZirconTerm\nzircon-[0-9]{4}\n", "utf8")
    const blacklist = createBlacklist({ path, ttlMs: -1 })
    const combined = (t: string) => blacklist.apply(scan(t))
    const cache = createScanCache(100, combined)
    const inputs = [CLEAN, SECRET, "zircon-0042", "zircon-[0-9]{4}", "ZirconTerm", mk("jwt"), ""]
    for (const s of inputs) {
        const direct = combined(s)
        const cached = cache.scan(s)
        assert.equal(cached.text, direct.text, `combined text parity: ${s}`)
        assert.deepEqual(
            cached.hits.map((h: any) => h.fp),
            direct.hits.map((h: any) => h.fp),
            `combined hit parity: ${s}`,
        )
    }
})

test("scan-cache: a combined blacklist hit is never cached", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sg-scan-combined2-")), "blacklist")
    writeFileSync(path, "ZirconTerm\n", "utf8")
    const blacklist = createBlacklist({ path, ttlMs: -1 })
    let calls = 0
    const combined = (t: string) => {
        calls++
        return blacklist.apply(scan(t))
    }
    const cache = createScanCache(10, combined)
    const first = cache.scan("ZirconTerm")
    assert.equal(cache.size, 0, "a blacklist hit must not create an entry")
    const second = cache.scan("ZirconTerm")
    assert.equal(calls, 2, "the combined scanner must run again")
    assert.ok(first.hits.length > 0 && second.hits.length > 0)
    assert.deepEqual(
        first.hits.map((h: any) => h.fp),
        second.hits.map((h: any) => h.fp),
    )
})

// ─────────────────────────────────────────────────────────────────────────────
// 3.2 — bound, eviction, clear, disabled
test("scan-cache: LRU bound and eviction", () => {
    const { fn, calls } = counting()
    const cache = createScanCache(2, fn)
    cache.scan("clean one")
    cache.scan("clean two")
    assert.equal(cache.size, 2)
    cache.scan("clean three") // evicts "clean one"
    assert.ok(cache.size <= 2, "size must never exceed the bound")
    const before = calls()
    cache.scan("clean one") // evicted -> re-scan
    assert.equal(calls(), before + 1, "evicted entry must be re-scanned")
})

test("scan-cache: clear empties the cache", () => {
    const { fn, calls } = counting()
    const cache = createScanCache(10, fn)
    cache.scan(CLEAN)
    assert.equal(cache.size, 1)
    cache.clear()
    assert.equal(cache.size, 0)
    cache.scan(CLEAN)
    assert.equal(calls(), 2, "cleared entry must be re-scanned")
})

test("scan-cache: a non-positive maximum disables caching", () => {
    const { fn, calls } = counting()
    const cache = createScanCache(0, fn)
    cache.scan(CLEAN)
    cache.scan(CLEAN)
    assert.equal(calls(), 2)
    assert.equal(cache.size, 0)
})

test("scan-cache: default bound constant", () => {
    assert.equal(SCAN_CACHE_MAX, 1000)
})

// ─────────────────────────────────────────────────────────────────────────────
// 3.3 — factory lifecycle (dispose releases the registration, so a later call
// for the same root registers again; the same-root duplicate while live stays a
// no-op and is pinned in loaded-log.test.mts)
test("scan-cache: factory dispose resolves and releases the root", async () => {
    const factory = await loadFactory()
    const hooks = await factory({ client: {}, directory: "/tmp" })
    await hooks.dispose()
    const again = await factory({ client: {}, directory: "/tmp" })
    assert.equal(typeof (again as { dispose?: unknown }).dispose, "function", "the disposed root registers again")
})
