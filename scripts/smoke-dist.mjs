// Smoke test for the packaged bundle. Run after `npm run build`:
//   npm run smoke:dist
import { join } from "node:path"
import { ensureIsolatedTestTmp } from "./test-tmp.mjs"

// Isolate the process temp directory BEFORE importing the bundle (config reads
// SECURITY_GUARD_LOG at module load), so the smoke never touches the user's
// production log and leaves no temp artifacts behind. The project-local
// bootstrap is disabled so the smoke creates no `.security-guard/` in the
// working directory.
const root = ensureIsolatedTestTmp()
process.env.SECURITY_GUARD_LOG = join(root, "guard.log")
process.env.SECURITY_GUARD_PROJECT_DIR = "0"

const mod = await import("../dist/security-guard.js")
const keys = Object.keys(mod)
if (keys.length !== 1 || keys[0] !== "SecurityGuard") {
    console.error("smoke-dist: expected a single export 'SecurityGuard', got:", keys)
    process.exit(1)
}

const value = "api_key=" + "Xy9kQ2mN7vR4tW8zB5c"
const hooks = await mod.SecurityGuard({ client: {}, directory: process.cwd() })
const afterHook = hooks["tool.execute.after"]
if (typeof afterHook !== "function") {
    console.error("smoke-dist: hook 'tool.execute.after' is missing (plugin halted or failed to register)")
    process.exit(1)
}
const output = { title: "smoke", output: value, metadata: { note: value } }
await afterHook({ tool: "bash", sessionID: "s", callID: "c", args: {} }, output)

const leaked =
    String(output.output).includes("Xy9kQ2mN7vR4tW8zB5c") ||
    JSON.stringify(output.metadata).includes("Xy9kQ2mN7vR4tW8zB5c")
if (leaked) {
    console.error("smoke-dist: output was not redacted")
    process.exit(1)
}

console.log("smoke-dist: OK")
