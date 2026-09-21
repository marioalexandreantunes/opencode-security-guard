// Preloaded via `node --import` in every test worker: isolates the process temp
// directory under a private `sg-test-*` run root (so every `os.tmpdir()`
// allocation is cleaned on exit), routes logging into that root, and disables
// the project-local bootstrap so no suite creates `.security-guard/` (or edits
// `.gitignore`) in the repository. `??=` keeps an inherited value when the test
// runner spawns child processes.
import { join } from "node:path"
import { ensureIsolatedTestTmp } from "../scripts/test-tmp.mjs"

const root = ensureIsolatedTestTmp()
process.env.SECURITY_GUARD_LOG ??= join(root, "guard.log")
process.env.SECURITY_GUARD_PROJECT_DIR ??= "0"
