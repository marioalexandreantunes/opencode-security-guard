// security-guard test temp hygiene (fix-test-tmpdir-leak).
// Proves that the per-worker temp isolation cleans every direct `os.tmpdir()`
// allocation, that the stale sweep is age-safe and stamp-throttled, and that
// the entry points initialize the helper before loading anything else.
// Run: node --import ./tests/setup-env.mts --test --experimental-strip-types tests/security-guard/temp-hygiene.test.mts

import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { once } from "node:events"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { after, test } from "node:test"
import { fileURLToPath, pathToFileURL } from "node:url"
import { SWEEP_STAMP, sweepStaleRunRoots } from "../../scripts/test-tmp.mjs"

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../..")
const setupPath = join(repoRoot, "tests", "setup-env.mts")
// `--import` takes a module URL: a bare Windows drive path (`C:\...`) can be
// misparsed as a URL scheme, so pass the file URL form on every platform.
const setupUrl = pathToFileURL(setupPath).href
const sandbox = mkdtempSync(join(tmpdir(), "sg-hygiene-host-"))

after(() => rmSync(sandbox, { recursive: true, force: true }))

// Runs a real `--import` worker that allocates directly through `os.tmpdir()`.
// The host is pinned to the sandbox via the inherited SG_TEST_HOST_TMPDIR so
// the test never touches the machine's real temp directory.
const CHILD = [
    'const fs = require("node:fs"), os = require("node:os"), path = require("node:path");',
    "const tmp = os.tmpdir();",
    'const unit = fs.mkdtempSync(path.join(tmp, "sg-reloc-target-"));',
    'const blocker = path.join(tmp, "sg-reloc-blocker-fixture");',
    'fs.writeFileSync(blocker, "x");',
    "fs.writeFileSync(process.env.SG_HYGIENE_RESULT, JSON.stringify({ tmp, unit, blocker, root: process.env.SG_TEST_ROOT || null }));",
    'if (process.env.SG_HYGIENE_FAIL === "1") process.exit(1);',
].join("\n")

const WORKER_DEADLINE_MS = 10_000
const KILL_GRACE_MS = 1_000
const RESULT_POLL_INTERVAL_MS = 20
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

type WorkerResult = {
    status: number | null
    signal: NodeJS.Signals | null
    error?: Error
    stdout: string
    stderr: string
    timedOut: boolean
}

const runWorker = async (extraEnv: Record<string, string> = {}): Promise<{ res: WorkerResult; resultPath: string }> => {
    const resultPath = join(sandbox, `result-${Math.random().toString(16).slice(2)}.json`)
    const env = { ...process.env, SG_TEST_HOST_TMPDIR: sandbox, SG_HYGIENE_RESULT: resultPath, ...extraEnv }
    delete env.NODE_TEST_CONTEXT
    const child = spawn(process.execPath, ["--import", setupUrl, "--experimental-strip-types", "-e", CHILD], {
        env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
    })
    let stdout = ""
    let stderr = ""
    let error: Error | undefined
    child.stdout?.setEncoding("utf8")
    child.stdout?.on("data", (chunk: string) => {
        stdout += chunk
    })
    child.stderr?.setEncoding("utf8")
    child.stderr?.on("data", (chunk: string) => {
        stderr += chunk
    })
    child.once("error", (cause) => {
        error = cause
    })

    const exit = once(child, "close").then(([status, signal]) => ({
        status: typeof status === "number" ? status : null,
        signal: signal ?? null,
    }))
    const deadline = Date.now() + WORKER_DEADLINE_MS
    while (!existsSync(resultPath) && child.exitCode === null && Date.now() < deadline) {
        await sleep(RESULT_POLL_INTERVAL_MS)
    }

    let exitResult = await Promise.race([exit, sleep(Math.max(0, deadline - Date.now())).then(() => null)])
    const timedOut = exitResult === null
    if (exitResult === null) {
        child.kill()
        const afterKill = await Promise.race([exit, sleep(KILL_GRACE_MS).then(() => null)])
        if (afterKill !== null) exitResult = afterKill
    }

    return {
        res: {
            status: exitResult?.status ?? null,
            signal: exitResult?.signal ?? null,
            error,
            stdout,
            stderr,
            timedOut,
        },
        resultPath,
    }
}

/**
 * Reads the worker's result, failing with the child's diagnostic state
 * (status/signal/error/stdout/stderr) when the file is missing — the Windows `ENOENT`
 * symptom is a child that never reached its write. The result must live
 * directly under the pinned sandbox, i.e. outside the worker's run root.
 */
const readResult = (res: WorkerResult, resultPath: string): any => {
    assert.ok(
        existsSync(resultPath),
        `the worker did not write its result (status=${res.status}, signal=${res.signal}, timedOut=${res.timedOut}, error=${
            res.error?.message ?? "none"
        }, stdout=${res.stdout || "(empty)"}, stderr=${res.stderr || "(empty)"})`,
    )
    assert.equal(dirname(resultPath), sandbox, "the result file must live outside the worker run root")
    return JSON.parse(readFileSync(resultPath, "utf8"))
}

test("temp-hygiene: a worker isolates and cleans direct allocations on exit", async () => {
    const { res, resultPath } = await runWorker()
    const info = readResult(res, resultPath)
    assert.equal(res.status, 0, res.stderr)
    assert.ok(info.root, "the worker must expose its isolated root")
    assert.ok(info.root.startsWith(sandbox), `root must live under the pinned host: ${info.root}`)
    assert.equal(info.tmp, info.root, "os.tmpdir() must be the isolated root")
    assert.ok(info.unit.startsWith(info.tmp), "a direct mkdtemp must land inside the root")
    assert.ok(info.blocker.startsWith(info.tmp), "a direct sg-reloc-blocker path must land inside the root")
    assert.equal(existsSync(info.root), false, "the run root must be removed after a clean exit")
})

test("temp-hygiene: a failing worker still cleans its run root", async () => {
    const { res, resultPath } = await runWorker({ SG_HYGIENE_FAIL: "1" })
    const info = readResult(res, resultPath)
    assert.equal(res.status, 1, res.stderr)
    assert.ok(info.root.startsWith(sandbox))
    assert.equal(existsSync(info.root), false, "the run root must be removed after a failing exit")
})

// Signals: the helper must remove the run root on SIGINT/SIGTERM and exit with
// the conventional status. POSIX-only: win32 signal semantics differ and the
// helper's signal cleanup is documented as best-effort there (design D1). The
// successful and intentionally-failing cleanup scenarios above stay mandatory
// on Windows; only this signal scenario is skipped there.
const CHILD_SIGNAL = [
    'const fs = require("node:fs");',
    'fs.writeFileSync(process.env.SG_HYGIENE_RESULT, process.env.SG_TEST_ROOT || "");',
    "setInterval(() => {}, 1000);",
].join("\n")

test("temp-hygiene: a worker removes its run root on SIGINT and SIGTERM", {
    skip: process.platform === "win32",
}, async () => {
    const cases = [
        ["SIGINT", 130],
        ["SIGTERM", 143],
    ]
    for (const [signal, expectedStatus] of cases) {
        const resultPath = join(sandbox, `signal-${signal}.json`)
        const env = { ...process.env, SG_TEST_HOST_TMPDIR: sandbox, SG_HYGIENE_RESULT: resultPath }
        delete env.NODE_TEST_CONTEXT
        const child = spawn(
            process.execPath,
            ["--import", setupUrl, "--experimental-strip-types", "-e", CHILD_SIGNAL],
            { env },
        )
        const deadline = Date.now() + 10000
        while (!existsSync(resultPath) && Date.now() < deadline) await sleep(20)
        assert.ok(existsSync(resultPath), `the child never reached its isolated root for ${signal}`)
        const root = readFileSync(resultPath, "utf8")
        assert.ok(root.startsWith(sandbox), `root must live under the pinned host: ${root}`)
        assert.equal(existsSync(root), true, "the run root must exist while the worker is alive")
        child.kill(signal)
        const [code] = await once(child, "exit")
        assert.equal(code, expectedStatus, `the handler must exit with the conventional status after ${signal}`)
        assert.equal(existsSync(root), false, "the run root must be removed after the interrupt")
    }
})

test("temp-hygiene: the sweep removes only old reserved directories", () => {
    const host = mkdtempSync(join(sandbox, "sweep-"))
    const oldDir = join(host, "sg-test-111-AAAAAA")
    const youngDir = join(host, "sg-test-222-BBBBBB")
    const otherDir = join(host, "unrelated-CCCCCC")
    const plainFile = join(host, "sg-test-file")
    for (const dir of [oldDir, youngDir, otherDir]) mkdirSync(dir)
    writeFileSync(plainFile, "x")

    const now = Date.now()
    const staleMs = 24 * 60 * 60 * 1000
    const oldSeconds = (now - 2 * staleMs) / 1000
    utimesSync(oldDir, oldSeconds, oldSeconds)

    const first = sweepStaleRunRoots({ hostDir: host, now, staleMs })
    assert.equal(first.removed, 1, "exactly the old reserved directory is removed")
    assert.equal(existsSync(oldDir), false)
    assert.equal(existsSync(youngDir), true, "a young root must remain")
    assert.equal(existsSync(otherDir), true, "a non-reserved directory must remain")
    assert.equal(existsSync(plainFile), true, "a non-directory entry must remain")
    assert.equal(existsSync(join(host, SWEEP_STAMP)), true, "the stamp must survive the directory sweep")
})

test("temp-hygiene: a fresh stamp throttles the scan; an expired one allows it", () => {
    const host = mkdtempSync(join(sandbox, "stamp-"))
    mkdirSync(join(host, "sg-test-333-CCCCCC"))
    const now = Date.now()
    const staleMs = 24 * 60 * 60 * 1000
    const stampTtlMs = 6 * 60 * 60 * 1000

    const first = sweepStaleRunRoots({ hostDir: host, now, staleMs, stampTtlMs })
    assert.equal(first.skipped, false)
    const second = sweepStaleRunRoots({ hostDir: host, now: now + 1000, staleMs, stampTtlMs })
    assert.equal(second.skipped, true, "a fresh stamp must skip the scan")
    const third = sweepStaleRunRoots({ hostDir: host, now: now + 10 * stampTtlMs, staleMs, stampTtlMs })
    assert.equal(third.skipped, false, "an expired stamp must allow the scan")
})

test("temp-hygiene: the sweep fails open on a missing host and on a bad entry", () => {
    assert.doesNotThrow(() => sweepStaleRunRoots({ hostDir: join(sandbox, "does-not-exist") }))
    const missing = sweepStaleRunRoots({ hostDir: join(sandbox, "does-not-exist") })
    assert.ok(missing.errors >= 1, "a missing host is counted as a fail-open error")

    const removed = []
    const dir = {
        readdirSync: () => [{ name: "sg-test-old" }, { name: "sg-test-bad" }, { name: "notes.txt" }],
        statSync: (path) => {
            if (path.endsWith("sg-test-bad")) throw new Error("boom")
            return { isDirectory: () => path.endsWith("sg-test-old"), mtimeMs: 0 }
        },
        rmSync: (path) => removed.push(path),
        writeFileSync: () => {},
    }
    const result = sweepStaleRunRoots({ hostDir: "/virtual", now: 10 * 24 * 60 * 60 * 1000, dir })
    assert.equal(result.removed, 1, "the good old directory is removed")
    assert.ok(result.errors >= 1, "the bad entry is isolated, not fatal")
    assert.ok(removed[0].endsWith("sg-test-old"))
})

test("temp-hygiene: entry points initialize the helper before loading anything else", () => {
    const setupSrc = readFileSync(join(repoRoot, "tests", "setup-env.mts"), "utf8")
    assert.ok(setupSrc.includes("test-tmp.mjs"), "setup-env must import the helper")
    assert.ok(
        setupSrc.indexOf("ensureIsolatedTestTmp") < setupSrc.indexOf("SECURITY_GUARD_LOG"),
        "setup-env must isolate the temp dir before deriving the log path",
    )

    const smokeSrc = readFileSync(join(repoRoot, "scripts", "smoke-dist.mjs"), "utf8")
    const initAt = smokeSrc.indexOf("ensureIsolatedTestTmp")
    const bundleAt = smokeSrc.indexOf("dist/security-guard.js")
    assert.ok(
        initAt >= 0 && bundleAt >= 0 && initAt < bundleAt,
        "smoke must isolate the temp dir before importing the bundle",
    )

    const integrationSrc = readFileSync(join(repoRoot, "scripts", "integration-dist.mjs"), "utf8")
    const integrationInitAt = integrationSrc.indexOf("ensureIsolatedTestTmp")
    const integrationImportAt = integrationSrc.indexOf('"../dist/security-guard.js"')
    assert.ok(integrationSrc.includes("cleanupIsolatedTestTmp"), "integration must expose explicit cleanup")
    assert.ok(integrationSrc.includes("} finally {"), "integration must clean up on assertion failure")
    assert.ok(
        integrationInitAt >= 0 && integrationImportAt >= 0 && integrationInitAt < integrationImportAt,
        "integration must isolate the temp dir before importing the bundle",
    )

    const helperSrc = readFileSync(join(repoRoot, "scripts", "test-tmp.mjs"), "utf8")
    const specifiers = [...helperSrc.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1])
    assert.ok(specifiers.length > 0)
    for (const specifier of specifiers) {
        assert.ok(specifier.startsWith("node:"), `the helper must only import node: builtins, saw ${specifier}`)
    }

    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"))
    assert.ok(pkg.scripts.test.includes("--test-concurrency=4"), "npm test must cap the file-level concurrency")
})
