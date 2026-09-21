import assert from "node:assert/strict"
import { execFileSync, spawnSync } from "node:child_process"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { delimiter, dirname, join } from "node:path"
import { test } from "node:test"

const repoRoot = join(import.meta.dirname, "..", "..")
const installer = join(repoRoot, "scripts", "install-hooks.sh")
const hookTemplate = join(repoRoot, "scripts", "hooks", "pre-push")
const bashCandidates =
    process.platform === "win32"
        ? [
              join(process.env.ProgramFiles ?? "C:/Program Files", "Git", "bin", "bash.exe"),
              join(process.env.ProgramW6432 ?? "C:/Program Files", "Git", "bin", "bash.exe"),
          ]
        : ["bash"]
const bash = bashCandidates.find((candidate) => candidate === "bash" || existsSync(candidate)) ?? null
const bashEnv = bash
    ? {
          ...process.env,
          PATH: [bash === "bash" ? null : dirname(bash), process.env.PATH].filter(Boolean).join(delimiter),
      }
    : process.env

function createFixture() {
    const root = mkdtempSync(join(tmpdir(), "sg-hook-"))
    execFileSync("git", ["init", "--quiet", root])
    const scripts = join(root, "scripts")
    const hooks = join(scripts, "hooks")
    mkdirSync(hooks, { recursive: true })
    writeFileSync(join(scripts, "install-hooks.sh"), readFileSync(installer))
    writeFileSync(join(hooks, "pre-push"), readFileSync(hookTemplate))
    const failureVariable = "${" + "HOOK_TEST_FAIL:-0}"
    writeFileSync(
        join(scripts, "quality-gate.sh"),
        `#!/usr/bin/env bash\nset -euo pipefail\n[ "${failureVariable}" -eq 0 ]\n`,
    )
    chmodSync(join(scripts, "install-hooks.sh"), 0o755)
    chmodSync(join(hooks, "pre-push"), 0o755)
    chmodSync(join(scripts, "quality-gate.sh"), 0o755)
    return { root, hook: join(root, ".git", "hooks", "pre-push"), installer: join(root, "scripts", "install-hooks.sh") }
}

function runInstaller(fixture: ReturnType<typeof createFixture>, ...args: string[]) {
    return spawnSync(bash ?? "bash", [fixture.installer, ...args], {
        cwd: fixture.root,
        env: bashEnv,
        encoding: "utf8",
    })
}

function resultMessage(result: ReturnType<typeof runInstaller>) {
    return `${result.stderr}${result.stdout}${result.error?.message ?? ""}`
}

test("hook installer installs the template into a clean repository", { skip: bash === null }, () => {
    const fixture = createFixture()
    const result = runInstaller(fixture)
    assert.equal(result.status, 0, resultMessage(result))
    assert.equal(readFileSync(fixture.hook, "utf8"), readFileSync(hookTemplate, "utf8"))
})

test("hook installer backs up an existing hook before replacing it", { skip: bash === null }, () => {
    const fixture = createFixture()
    const original = "#!/usr/bin/env bash\necho existing\n"
    writeFileSync(fixture.hook, original)

    const result = runInstaller(fixture)
    const backup = `${fixture.hook}.security-guard-backup`
    assert.equal(result.status, 0, resultMessage(result))
    assert.equal(readFileSync(backup, "utf8"), original)
    assert.equal(readFileSync(fixture.hook, "utf8"), readFileSync(hookTemplate, "utf8"))
})

test("hook installer refuses a second replacement when the backup already exists", { skip: bash === null }, () => {
    const fixture = createFixture()
    const original = "#!/usr/bin/env bash\necho existing\n"
    writeFileSync(fixture.hook, original)
    writeFileSync(`${fixture.hook}.security-guard-backup`, "older backup\n")

    const result = runInstaller(fixture)
    assert.equal(result.status, 1)
    assert.match(result.stderr, /backup already exists/)
    assert.equal(readFileSync(fixture.hook, "utf8"), original)
})

test("hook installer allows an explicit force replacement", { skip: bash === null }, () => {
    const fixture = createFixture()
    writeFileSync(fixture.hook, "#!/usr/bin/env bash\necho existing\n")

    const result = runInstaller(fixture, "--force")
    assert.equal(result.status, 0, resultMessage(result))
    assert.equal(readFileSync(fixture.hook, "utf8"), readFileSync(hookTemplate, "utf8"))
})

test("installed pre-push hook propagates gate failures and succeeds when gates pass", { skip: bash === null }, () => {
    const fixture = createFixture()
    assert.equal(runInstaller(fixture).status, 0)

    const failed = spawnSync(bash ?? "bash", [fixture.hook], {
        cwd: fixture.root,
        env: { ...bashEnv, HOOK_TEST_FAIL: "1" },
        encoding: "utf8",
    })
    assert.equal(failed.status, 1)
    assert.match(failed.stderr, /REJECTED/)

    const passed = spawnSync(bash ?? "bash", [fixture.hook], { cwd: fixture.root, env: bashEnv, encoding: "utf8" })
    assert.equal(passed.status, 0, passed.stderr)
    assert.match(passed.stdout, /gates passed/)
    assert.ok(existsSync(fixture.hook))
})
