// scripts/test-tmp.mjs — per-process temp isolation for tests and the smoke run.
//
// Every `node --test` worker preloads `tests/setup-env.mts`, which calls
// `ensureIsolatedTestTmp()` before any production import. The helper:
//   1. records the true host temp directory in `SG_TEST_HOST_TMPDIR`
//      (an inherited value wins, so nested runs still point at the real host);
//   2. creates one private run root `<host>/sg-test-<pid>-<rand>`;
//   3. points `TMPDIR`/`TMP`/`TEMP` at it, so every existing `os.tmpdir()`
//      allocation (including direct `mkdtempSync` and `sg-reloc-blocker-*`
//      paths) lands inside the root;
//   4. removes the root on normal exit and on SIGINT/SIGTERM;
//   5. sweeps stale run roots left by hard-killed workers, throttled by a
//      fixed stamp file so a worker flood never rescans a huge host directory.
//
// `SIGKILL` cannot run JavaScript; those roots are reclaimed by the next sweep
// once they are older than one day. The helper imports `node:` builtins only,
// so preloading it never pulls project code into a worker.
import { mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

/** Reserved prefix for per-process run roots. */
export const RUN_ROOT_PREFIX = "sg-test-"
/** Coordination stamp; deliberately not under `sg-test-` so it is not counted as a root. */
export const SWEEP_STAMP = "security-guard-test-sweep.stamp"
const STALE_MS = 24 * 60 * 60 * 1000
const STAMP_TTL_MS = 6 * 60 * 60 * 1000

/** @type {string | null} */
let isolatedRoot = null
let cleanupIsolatedRoot = () => {}

/**
 * @param {string} path
 */
const removeDir = (path) => {
    try {
        rmSync(path, { recursive: true, force: true })
    } catch {
        /* best effort: a locked file must not fail the run */
    }
}

/**
 * Options for {@link sweepStaleRunRoots}; every field except `hostDir` has a
 * default, and the filesystem/clock entries are injectable for tests.
 *
 * @typedef {object} SweepOpts
 * @property {string} [hostDir]
 * @property {number} [now]
 * @property {number} [staleMs]
 * @property {number} [stampTtlMs]
 * @property {string} [stamp]
 * @property {{ readdirSync: typeof readdirSync, rmSync: typeof rmSync, statSync: typeof statSync, writeFileSync: typeof writeFileSync }} [dir]
 * @property {(error: unknown) => void} [log]
 */

/**
 * Remove reserved run roots older than `staleMs` under `hostDir`, throttled by
 * a stamp file. Fail-open: never throws, isolates per-entry errors. The
 * directory, clock and filesystem are injectable for deterministic tests.
 *
 * @param {SweepOpts} [opts]
 */
export function sweepStaleRunRoots({
    hostDir,
    now = Date.now(),
    staleMs = STALE_MS,
    stampTtlMs = STAMP_TTL_MS,
    stamp = SWEEP_STAMP,
    dir = { readdirSync, rmSync, statSync, writeFileSync },
    log = () => {},
} = {}) {
    const result = { skipped: false, removed: 0, errors: 0 }
    // Fail-open without a host directory: the old code threw inside the try
    // below (join of `undefined`) and returned the same single-error result.
    if (typeof hostDir !== "string") {
        result.errors++
        return result
    }
    try {
        const stampPath = join(hostDir, stamp)
        try {
            if (now - dir.statSync(stampPath).mtimeMs < stampTtlMs) {
                result.skipped = true
                return result
            }
        } catch {
            /* no stamp yet: sweep */
        }
        let entries
        try {
            entries = dir.readdirSync(hostDir, { withFileTypes: true })
        } catch (e) {
            result.errors++
            log(e)
            return result
        }
        for (const entry of entries) {
            const name = typeof entry === "string" ? entry : entry.name
            if (name === stamp || !name.startsWith(RUN_ROOT_PREFIX)) continue
            const full = join(hostDir, name)
            try {
                if (!dir.statSync(full).isDirectory()) continue
                if (now - dir.statSync(full).mtimeMs <= staleMs) continue
                dir.rmSync(full, { recursive: true, force: true })
                result.removed++
            } catch (e) {
                result.errors++
                log(e)
            }
        }
        try {
            dir.writeFileSync(stampPath, `${new Date(now).toISOString()}\n`)
        } catch (e) {
            result.errors++
            log(e)
        }
    } catch (e) {
        result.errors++
        log(e)
    }
    return result
}

/**
 * Idempotently isolate the current process under a private run root. Returns
 * the root path (also exposed as `process.env.SG_TEST_ROOT`).
 */
export function ensureIsolatedTestTmp() {
    if (isolatedRoot) return isolatedRoot
    const host = process.env.SG_TEST_HOST_TMPDIR || tmpdir()
    process.env.SG_TEST_HOST_TMPDIR = host
    sweepStaleRunRoots({ hostDir: host })
    const root = mkdtempSync(join(host, `${RUN_ROOT_PREFIX}${process.pid}-`))
    process.env.TMPDIR = root
    process.env.TMP = root
    process.env.TEMP = root
    process.env.SG_TEST_ROOT = root
    isolatedRoot = root

    let cleaned = false
    const cleanup = () => {
        if (cleaned) return
        cleaned = true
        removeDir(root)
        isolatedRoot = null
        cleanupIsolatedRoot = () => {}
    }
    cleanupIsolatedRoot = cleanup
    process.once("exit", cleanup)
    for (const signal of ["SIGINT", "SIGTERM"]) {
        process.once(signal, () => {
            cleanup()
            process.exit(signal === "SIGINT" ? 130 : 143)
        })
    }
    return root
}

/** Remove the current process run root immediately, if one exists. */
export function cleanupIsolatedTestTmp() {
    cleanupIsolatedRoot()
}
