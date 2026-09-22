# opencode-security-guard

![Technical overview of the OpenCode Security Guard architecture and data flow](https://i.imgur.com/uH9O3hP.png)

> CI status: GitHub Actions validates the supported Linux and Windows matrix on
> every push to `main` and pull request. The scheduled workflow runs mutation
> and property gates.

Project started on 17 August 2026.

An [opencode](https://opencode.ai) plugin that protects the **inference boundary**: it keeps secrets (API keys, tokens, passwords, private keys) from leaving your environment and reaching the model. It works in five layers:

1. **`tool.execute.before`**: blocks reads/writes/patches of sensitive files and dangerous `bash` commands (env dumps, secret exfiltration, marker write-back).
2. **`tool.execute.after`**: redacts the output of every tool recursively: text, title, metadata values **and keys**, attachments and any other nested field; on failure the whole output is suppressed (fail-closed).
3. **`chat.message`**: redacts your prompt before it leaves for the model provider.
4. **`experimental.chat.messages.transform`**: last line of defence over the whole history sent to inference (message `parts` **and** `info`: `system`, `summary`, `error`, `path`).
5. **`experimental.chat.system.transform`**: redacts the system prompt before it leaves for the provider.

## Cross-platform

Runs on **macOS, Linux and Windows** with no native modules (Node built-ins only), and its detection is platform-aware:

- Windows separators (`\`) are normalized to `/`; drive-letter (`C:\...`) and UNC (`\\server\share`) paths are recognized;
- path matching is case-insensitive (Windows/macOS file systems);
- shell heuristics cover POSIX, PowerShell (`Get-ChildItem env:`, `Set-Content`, `iwr`/`Invoke-RestMethod`, `Get-Content`, …), and cmd (`set`, `type`, `copy`, `move`, `ren`, …).

## Detection

The scanner (`src/rules.ts`) is heuristic and zero-dependency: **53 regex rules** (plus the decode-pass `encoded-secret` label) + Shannon entropy, gated by a cheap pre-filter.

- **Provider tokens:** a curated high-signal corpus with exact prefixes/lengths (AWS, AWS STS, GitHub, GitHub fine-grained PAT, GitLab, npm, PyPI, Twilio, SendGrid, Mailgun, Discord, Heroku, DigitalOcean, Shopify, Telegram, OpenAI, Anthropic, Hugging Face, Google OAuth, Azure, Slack app-level, Stripe restricted, Grafana, Docker, Vault, Tailscale, Groq, xAI, Replicate, Perplexity, Pulumi, Render, Doppler, Resend, Brevo, Linear, …). Context-sensitive rules require a nearby keyword where a bare format is ambiguous: the Heroku rule only fires on a UUID next to `heroku`, never on a bare UUID.
- **JSON credential fields:** quoted fields whose names contain `apiKey`/`api_key`, `Authorization`, `token`, `secret`, `accessKey`, `privateKey`, `password` or related forms are redacted even when the value uses a provider-specific format. This covers nested configuration such as MCP headers, `QDRANT_API_KEY`, and provider `options.apiKey` values including `ix_…` and `sk-or-v1-…` prefixes. Whole-value placeholders remain allowlisted.
- **Encoded secrets:** base64 (standard + url-safe), hex and percent-encoded blobs are decoded **once** (no recursion) and re-scanned. The **original encoded span** is redacted and stored in the vault, so write-back is byte-for-byte identical (no file corruption).
- **Allowlist:** built-in exact documentation/example values (and whole-value placeholders) are never redacted; a real secret that merely contains such a word is still redacted.
- **Bounds:** a plaintext pre-filter plus a separate encoded-candidate pre-filter gate the work; decoding is capped (≤ 4 KB per payload, ≤ 16 candidates per scan, highest-entropy first).

### Shell and environment detection

`src/bash.ts` keeps the conservative block policy. It always blocks:

- **env/variable dumps**: POSIX (`env`, `printenv`, `set`, `export -p`, `declare -p`, `readonly -p`, `compgen -v`), PowerShell (`Get-Item Env:`, `Get-ChildItem Env:`, `[Environment]::GetEnvironmentVariable`, `$env:`) and cmd (`cmd /c set`);
- **interpreter env reads**: `os.environ`/`os.getenv`, `process.env`, `ENV[`, `getenv` and the PHP superglobals (`$_ENV`, `$_SERVER`, `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, `$_FILES`, `$_SESSION`), `%ENV`, `System.getenv`, `Deno.env` (≥ 9 detectors);
- **secret-bearing eval/substitution**: `echo $(printenv TOKEN)`, backticks, and a secret piped into `sh`/`bash`/`zsh`.

File processors (`sed`, `jq`, `base64`, `tar`, `gpg`, …) and interpreter file reads (`open('.env')`, `fs.readFileSync('.env')`) block **only** when a sensitive path is involved. Ordinary commands (`ls`, `git`, `grep`, `cat README.md`, `jq . package.json`) keep passing. The patterns are data-driven and anchored to command position to keep false positives low.

### History scan memoization

`experimental.chat.messages.transform` re-scans the whole history on every turn. The plugin keeps a bounded LRU cache (`createScanCache`, `SCAN_CACHE_MAX = 1000`) of **negative** results, meaning strings that produced no hits. The cache wraps the **combined scanner** (secrets + team blacklist), so a hit of either kind prevents caching and a blacklist reload clears the cache. It never stores secret values, lives in memory only, and is cleared on `dispose`. This removes the per-string scanner cost for unchanged or clean strings, but not the per-turn history traversal.

## Installation

> **Private:** the plugin is not published on npm yet. Use one of the local options below.

### 1. Build and install (recommended)

```sh
npm install
npm run build        # produces dist/security-guard.js + dist/security-guard.d.ts
```

Install the bundle into the global plugins directory with the provided script (it runs `npm run build` and copies `dist/security-guard.js`, creating the destination folder if needed):

**macOS / Linux:**

```sh
./scripts/install-mac.sh
```

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
```

The scripts derive the repository root from their own location and copy to `~/.config/opencode/plugins/security-guard.js` (`$env:USERPROFILE\.config\opencode\plugins\security-guard.js` on Windows).

Or copy the bundle manually:

**macOS / Linux:**

```sh
cp ./dist/security-guard.js ~/.config/opencode/plugins/security-guard.js
```

**Windows (PowerShell):**

```powershell
Copy-Item "C:\path\to\security-guard\dist\security-guard.js" "$env:USERPROFILE\.config\opencode\plugins\security-guard.js"
```

opencode auto-discovers any `*.ts`/`*.js` in `~/.config/opencode/plugins/` (global) or `.opencode/plugins/` (project).

### 2. Reference in `opencode.json` (development)

Point to the bundle (or to the `src/index.ts` entry, if opencode resolves the repository's TS imports):

```json
{
  "plugin": ["file:///path/to/security-guard/dist/security-guard.js"]
}
```

### 3. When published

```sh
opencode plugin add opencode-security-guard
```

> Do not install in more than one place at the same time. After changing the installation, restart opencode (config is only read at startup).

### Why is the code `.ts` and the `dist/` `.js`?

The source lives in several `.ts` modules: `src/config.ts`, `src/vault.ts`, `src/rules.ts`, `src/blacklist.ts`, `src/redact.ts`, `src/tool-output.ts`, `src/paths.ts`, `src/write-policy.ts`, `src/bash.ts`, `src/project-dir.ts`, `src/plugin.ts`, `src/index.ts` (TypeScript is the development language: types and `npm run typecheck`). `tsup` compiles and **bundles everything into a single `dist/security-guard.js`** (ESM) + `dist/security-guard.d.ts`. `package.json` points to this bundle through `main` and `exports`, and you copy it into `plugins/`.

**Do I need to compile?** To install locally, yes: since the source is split into modules with relative imports, copying a single `.ts` is no longer enough. Alternatives: run `npm run build` and copy the bundle, or point `opencode.json` directly at the repository (if opencode resolves the TS imports). The `.js` is **mandatory when you publish** to npm.

⚠️ Keep only **one** installation method active. If you have the old (single-file) `.ts` and the `.js` bundle in `plugins/` at the same time, both register. They are distinct modules, so the internal idempotency guard does not recognise them as the same.

## Configuration

Everything is optional, via environment variables:

| Variable | Description | Default |
| --- | --- | --- |
| `SECURITY_GUARD_LOG` | Log file path (overrides the project-local log) | `<projectRoot>/.security-guard/security-guard.log`, else `<tmpdir>/opencode-security-guard.log` |
| `SECURITY_GUARD_PROJECT_DIR` | `0` disables the `.security-guard/` bootstrap (no directory, no project log, no default blacklist) | active |
| `SECURITY_GUARD_BLACKLIST` | Explicit blacklist file (wins over the project path; loads even with the bootstrap disabled) | `<projectRoot>/.security-guard/blacklist` |
| `SECURITY_GUARD_BLACKLIST_TTL_MS` | Blacklist reload poll interval, ms (`0` = every hook, `-1` = never) | `2000` |
| `SECURITY_GUARD_LOG_LEVEL` | Minimum level written: `debug`, `info`, `warn`, `error` | `info` |
| `SECURITY_GUARD_MODE` | `redact` (redact) or `block` (block reads) | `redact` |
| `SECURITY_GUARD_EXTRA_PATHS` | Extra sensitive path regexes, `;`-separated | none |
| `SECURITY_GUARD_QUIET` | `1` disables toasts (logging continues) | none |
| `SECURITY_GUARD_REHYDRATE` | `0` disables rehydration in `write`/`edit` | active |
| `SECURITY_GUARD_REHYDRATE_BASH` | `1` enables rehydration in `bash` (anti-exfil gate) | disabled |
| `SECURITY_GUARD_REHYDRATE_EXTERNAL` | `1` allows materialising a known marker outside the project worktree | disabled |
| `SECURITY_GUARD_VAULT_MAX` | Max vault entries (LRU) | `1000` |

Example:

```sh
SECURITY_GUARD_MODE=block opencode
```

## Project directory (`.security-guard/`)

On load, the plugin bootstraps a project-local directory at the project root. A non-root git worktree is preferred; when OpenCode supplies a filesystem-root `worktree` as its global placeholder and a concrete non-root `directory` is available, the plugin uses `directory` instead. If neither value is usable, it falls back to `cwd`. Its contents are ignored by git and the directory itself is a sensitive path: the agent cannot write it, and reads are blocked (`SECURITY_GUARD_MODE=block`) or read-then-redacted (`redact`, the default), while the plugin accesses it directly through `fs`. Disable everything with `SECURITY_GUARD_PROJECT_DIR=0`.

```
<projectRoot>/.security-guard/
├─ security-guard.log      # per-project log (rotation .log.1); SECURITY_GUARD_LOG overrides
├─ blacklist               # team denylist (edit manually)
├─ blacklist.example       # grammar guide, versionable example
├─ halt.example            # how to disable the guard (copy to "halt")
└─ .gitignore              # "*", written when the root has no .gitignore and is not a git worktree
```

- The directory is created on load; an existing one is never overwritten (idempotent).
- The root `.gitignore` gains `/.security-guard/*` plus `!/.security-guard/blacklist.example` and `!/.security-guard/halt.example`; an older generated block is upgraded with the missing `halt.example` exception. A plain `.security-guard/` line counts as "already ignored" and is left intact. Git then never descends into the directory, so versioning the examples requires dropping that legacy line or `git add -f`.
- Every step is fail-open: a failure is logged (`project-dir.failed`) and never blocks the plugin; if the project log cannot be created, the temp fallback path is kept.
- Reads and shell references to `.security-guard/**` are blocked or redacted by the sensitive-path policy; `write`/`edit`/`patch` are always blocked.

### Kill switch (halt)

Creating `<projectRoot>/.security-guard/halt` disables the guard for that project (the git worktree, or the opencode `directory` when there is no worktree). On a fresh plugin load, the factory logs `halted` and registers no hooks. Presence is all that matters. The shipped `halt.example` opens with `plugin disabled` and explains the copy, but the content is never read. Remove the file to re-enable the guard. The check runs after bootstrap and before hook registration. A running instance must first be disposed or restarted before a new `halt` state is observed. `SECURITY_GUARD_PROJECT_DIR=0` also disables the check.

To verify the kill switch without putting a real-looking secret in a command, run this fresh-factory probe from the project root. It generates a pseudo-key only in memory and checks whether the bash hook exists; it does not execute the command or write the key anywhere:

```sh
node --experimental-strip-types --input-type=module -e 'import { randomBytes } from "node:crypto"; const { SecurityGuard } = await import("./src/index.ts"); const hooks = await SecurityGuard({ client: {}, directory: process.cwd(), worktree: process.cwd() }); const pseudoKey = `sk-proj-${randomBytes(24).toString("base64url")}`; const before = hooks["tool.execute.before"]; if (typeof before !== "function") { console.log("HALTED: pseudo-key probe had no tool hook to block it"); } else { let blocked = false; try { await before({ tool: "bash", sessionID: "probe", callID: "probe" }, { args: { command: `printf "%s\\n" "${pseudoKey}"` } }); } catch { blocked = true; } console.log(blocked ? "ACTIVE: pseudo-key was blocked" : "ACTIVE: pseudo-key was allowed"); }'
```

Expected output without a `halt` file:

```text
ACTIVE: pseudo-key was blocked
```

Expected output when `halt` is present:

```text
HALTED: pseudo-key probe had no tool hook to block it
```

> **Important:** `halt` disables all security-guard hooks for the worktree, including secret detection, redaction and blocking. Use it only in an isolated development repository while testing code that handles keys. Never use real credentials in this mode or commit them to the repository. Remove `halt` and restart/reload opencode before returning to protected operation.

### Team blacklist

`<projectRoot>/.security-guard/blacklist` is line-based text. Edit it in your editor; the plugin picks up changes by mtime (poll `SECURITY_GUARD_BLACKLIST_TTL_MS`, default 2000 ms; `0` = every hook, `-1` = never) and invalidates the scan cache on reload.

- one term per line, matched case-insensitively as a substring;
- plain terms are literal: regex metacharacters (e.g. `*`) are not wildcards. Use a `re:` line for patterns;
- blank lines and `#` comments are ignored;
- a `re:` prefix compiles a case-insensitive regular expression; an invalid one is skipped and logged (`blacklist.invalid`) without aborting the load.

```
# .security-guard/blacklist
AcmeProjectCodename
internal.acme.example
re:acme-[0-9]{4}
re:apikey_[0-9a-f]+(?:_[0-9a-f]+)*
```

Matches are redacted at the inference boundary exactly like secrets (`chat.message`, the history transform, the system prompt and tool output), replaced by `<MARKER:blacklist:hash>` whose hash derives from the exact observed match (including its casing), and rehydrated through the vault like a secret marker. The declared literal casing or `re:` pattern is matching configuration only and is never written back. The blacklist is **not** applied to `bash` commands or to on-disk write-target inspection (inference boundary only). An explicit `SECURITY_GUARD_BLACKLIST` wins over the project file and loads even with `SECURITY_GUARD_PROJECT_DIR=0`.

## Threat model

The guard protects the inference boundary: it stops secrets from being read, echoed, or re-sent to the model. Detection is heuristic (regex + Shannon entropy) and deliberately conservative:

- **fail-closed:** if redaction fails, the output is suppressed;
- tuned not to over-redact ordinary identifiers, version strings, and the `obfstr!` literals commonly used everywhere.

### Known limitations

- Detection is heuristic: unknown, short or low-entropy secrets, Unicode-obfuscated values and unusual shell syntax may pass. PII is not detected.
- Scanning targets text strings and UTF-8 files, not buffers, streams or arbitrary binary data. For a full `write` with rehydration disabled, valid links are followed and their destinations are inspected; a missing or verified-clean target is allowed, while an oversized, non-regular, dangling-link, unreadable or metadata-inaccessible target is blocked as unverifiable. With rehydration enabled, this disk-inspection policy does not run.
- Encoded values shorter than 20 characters, malformed/non-UTF-8 content and nested encodings may not be decoded. Decoding checks the 16 highest-entropy candidates per scan, up to 4 KiB each; base64 containing `/` may be split by the entropy rule.
- Prompt injection, per-rule severity levels and external/JSON rule packs are out of scope.
- `$VAR` and globs are not resolved in paths. `bash` checks paths lexically; file-tool destinations resolve symlinks and junctions canonically. Deleting sensitive files with `del`/`rm` is not blocked.
- Shell and network checks are heuristic. Opaque pipes, aliases, indirect expansion and obfuscated network commands may evade detection; markers copied into network commands remain a residual risk.
- Rehydration writes secrets to disk by design. It is restricted to the canonical worktree unless `SECURITY_GUARD_REHYDRATE_EXTERNAL=1`; `SECURITY_GUARD_REHYDRATE_BASH=1` also permits shell destinations outside that policy.
- `experimental.chat.system.transform` relies on in-place mutation supported by the JS runtime; re-check after runtime upgrades. `messages.transform` remains the effective fallback boundary.
- The scan cache avoids repeated per-string work but still traverses the full history each turn. Logs remain project-local, sanitized and isolated per project; `SECURITY_GUARD_LOG` can override the default location.
- The blacklist is plaintext, inference-boundary only and rehydratable like secrets. Matching is case-insensitive substring matching, while user-owned `re:` patterns have no ReDoS protection.
- `.security-guard/**` is sensitive, so the agent cannot manage the team list; edit it manually using `blacklist.example` as a guide.

## Rehydration (vault + placeholders)

The guard hides secrets from the model: when the agent reads a file containing a key, it sees a marker instead of the real value.

This is the plugin's core boundary: credentials remain available to local tool execution, but never enter the inference context or reach the model provider. The worktree is not read-only. The agent can continue to work with ordinary files locally, while the guard protects sensitive destinations, unsafe commands and network exfiltration.

```
API_KEY=<MARKER:secret-assignment:9f2c1a4b6d8e0f31>
```

That protects the model, but creates a problem: if the agent wants to **write** a config file with that key, it only has the marker. Writing the marker would corrupt the file.

**Rehydration** solves this: the real value is returned **at the last moment**, only when a tool is about to run (`write`/`edit`/`bash`). It never reaches the model.

Think of a **hotel key card**: the model gets a demo card (the marker); when it needs to open the door (run the tool), the front desk (the *vault*) swaps it for the real key, opens the door, and puts it back. The model never holds the real key.

### How it works: local rehydration, provider-safe inference

The marker is a capability reference, not the secret itself. It lets the local plugin restore an already-known value at the last possible moment, after the model has finished deciding what tool call to make:

![Vault rehydration flow: the model sees a marker while the local vault restores the secret only before tool execution](https://i.imgur.com/A6HB6qd.png)

1. The agent reads `.env` → sees `API_KEY=<…:9f2c1a4b6d8e0f31>`.
2. The plugin stores it in the **vault** (an in-memory table): `9f2c1a4b6d8e0f31 → "sk_live_51AbC..."`.
3. The agent writes a new file containing `<…:9f2c1a4b6d8e0f31>`.
4. **Before** the `write` runs, the plugin replaces the marker with the real value → the file ends up with the correct key.
5. The model still has **never seen** the key.

The result is deliberate: local development remains useful, including writing configuration files that need credentials, but the plaintext credential is kept on the local execution side of the boundary. The provider receives the redacted marker and surrounding context, never the vault value.

### The vault

| Hash (of the marker) | Real value |
| --- | --- |
| `9f2c1a4b6d8e0f31` | `sk_live_51AbC...` |
| `7b3e9d0c5a1f2846` | `ghp_xxxxxxxx...` |

- Lives only while opencode is open; **never** written to disk or to the log.
- Has a limit with LRU policy (`SECURITY_GUARD_VAULT_MAX`, default 1000).
- Is cleared when the plugin terminates (`dispose`).
- Marker identities are **opaque per process**: a 16-hex HMAC-SHA256 of the observed value under a random per-process key. The same value reuses its marker within a run, but markers are unlinkable across runs. This prevents dictionary comparison unlike a deterministic unsalted fingerprint.

### Security rules

- **Unknown** marker (not in the vault) → **blocked** (never writes the literal placeholder).
- `write`/`edit` rehydrate **by default**; disable with `SECURITY_GUARD_REHYDRATE=0`.
- A known marker is rehydrated only when every destination resolves inside the canonical project worktree; writing outside it requires `SECURITY_GUARD_REHYDRATE_EXTERNAL=1` (logged as a `rehydrated.external` warning). Destinations that cannot be inspected are treated as outside. The boundary is a point-in-time check, not an OS sandbox: a directory swapped after validation is a residual race.
- `bash` only rehydrates with `SECURITY_GUARD_REHYDRATE_BASH=1` **and** if the command has no network verbs (`curl`, `wget`, `ssh`, …). This prevents exfiltration of a marker copied by the model. Bash rehydration is exempt from the worktree policy because shell destinations are heuristic.
- The most sensitive targets (`.env`, `.ssh/`, `*.pem`, …) are still blocked by the sensitive-path list, including through innocent-named links that resolve to them; arguments that cannot be inspected for markers are blocked with the coded `blocked.marker-inspection` diagnostic instead of throwing.

## Diagnostics

The guard's own diagnostics are designed not to become a leak channel (log schema revision `12`):

- The log (`<projectRoot>/.security-guard/security-guard.log`) never contains secret values, blacklist terms, raw `SECURITY_GUARD_EXTRA_PATHS` patterns, or raw shell command text. Blocked `bash` events record the event name, tool, session/call identifiers, rule patterns and a project-root-relative `file` only.
- Invalid `SECURITY_GUARD_EXTRA_PATHS` entries are reported as `config.invalid-path` with `{ index, error: "invalid-regular-expression" }`. The log never includes the pattern or engine message.
- Bootstrap failures are reported as `project-dir.failed` with a stable `{ step, error }`. The `error` value is `mkdir-failed`, `write-failed` or `io-error`; the log never includes the platform message or an absolute path.
- Write arguments that cannot be inspected for markers are reported as `blocked.marker-inspection` with `{ tool, error: "marker-inspection-failed" }`. The log never includes argument content, marker text or engine messages.
- Full writes with rehydration disabled are reported as `blocked.write.fullrewrite` with `{ tool, file, reason }`, where `reason` is `contains-secrets`, `not-file`, `too-large`, `metadata-failed`, `dangling-link` or `read-failed`. Missing and verified-clean targets remain allowed; unverifiable existing targets are blocked. Raw filesystem errors are never logged or shown.
- User-facing messages (toasts, thrown errors) carry project-root-relative paths; the log-write stderr warning is generic and names no path.

## Development

```sh
npm install        # install dev dependencies
npm run typecheck  # type-check
npm run lint       # static analysis (Biome)
npm test           # regression suite (node --test + type stripping)
npm run test:property        # property/fuzz suite over the scanner (fixed seed, ~5 s)
npm run test:property:nightly # large-count run, random seed (prints SG_FUZZ_SEED)
SG_FUZZ_SEED=<seed> npm run test:property  # replay a specific run
npm run build      # build to dist/
npm run smoke:dist # import the built bundle and verify a redaction
```

The property suite (`tests/security-guard/property-scanner.mts`) is a **separate
gate** from `npm test`. It covers the scanner (rules, validators and decode pass)
with fast-check. Checks include per-rule true positives, pre-filter soundness,
marker stability, benign pass-through, decode budgets and security invariants.
The suite blocks merges in CI and runs nightly with a larger count. It is not
part of `npm test`, so Stryker's command runner and the c8 coverage gate are
unaffected.

### Mutation testing

The full Stryker gate runs with `npm run mutation` in scheduled CI. During local
iteration, scope the run to the changed production file and redirect output to a
log, for example:

```sh
npx stryker run --mutate src/paths.ts > stryker-paths.log 2>&1
```

Measured local Windows results from 2026-09-22 (`concurrency: 4`):

| Scope | Mutants | Duration | Mutation score | Result |
| --- | ---: | ---: | ---: | --- |
| `src/paths.ts` | 177 | 5m 07s | 100.00% | 173 killed, 4 timed out, 0 survived |
| `src/plugin.ts` | 673 | 48m 21s | 81.28% | 541 killed, 6 timed out, 126 survived |

These timings are observational, not performance guarantees. They vary with CPU,
background load, test duration and Stryker worker contention. Never run scoped
Stryker jobs concurrently; remove their logs and generated reports afterwards.

The build produces `dist/security-guard.js` + `dist/security-guard.d.ts` (ESM, no runtime dependencies). To test locally in a project, reference the bundle: `"plugin": ["file:///path/to/security-guard/dist/security-guard.js"]`. You can also reference the repository entry (`"plugin": ["./src/index.ts"]`) if opencode resolves the TS imports.

### Node runtime

The plugin requires **Node `>=22.6`** (`engines` in `package.json`). The full suite (456 tests) was validated on:

| Node | npm | Status |
| --- | --- | --- |
| 22.23.2 | 10.9.8 | ✓ project default (`.nvmrc`) |
| 24.21.0 | 11.19.0 | ✓ local run |
| 26.8.2 | 11.19.1 | ✓ local run |

Notes:

- Test files use Node type stripping (`.mts`); the `--experimental-strip-types` flag is required on 22.x and accepted as a no-op on 24.x/26.x, where type stripping is on by default.
- `node --test` switches its output from TAP (`# tests`) to the spec reporter (`ℹ tests`) from Node 24 on. Tooling that parses test logs must accept both.
- `npm run coverage` (c8 12) requires Node `>=22.12` (yargs 18 engine range); the plugin itself and the test suite still run on the declared `>=22.6` floor.
- With [nvm](https://github.com/nvm-sh/nvm), run `nvm use` inside the repository to pick up `.nvmrc`.
- The configured CI matrix (22.23/24/26 on Linux, 22.23.2 on Windows)
  re-validates these runtimes on every push to `main` and pull request. The
  supported matrix has passed after the GitHub migration.

### SDK compatibility

The plugin pins its `@opencode-ai/plugin` peer dependency to the exact SDK version it is built and validated against. The contract depends on `experimental.*` hook types, so no wider compatibility range is advertised.

| Dependency | Pinned version | Validation method |
| --- | --- | --- |
| `@opencode-ai/plugin` | `1.18.31` (peerDependency and devDependency) | `npm run typecheck` + `npm test` on the pinned version |

`peerDependencies` and the devDependency both resolve to `1.18.31`, so the installed SDK always matches the validated contract.

### Continuous integration

Quality gates are configured and enforced through GitHub Actions
(`.github/workflows/verify.yml`), the single CI source of truth. The retired
GitLab definition was removed as part of this change:

- Fast gates run on pushes to `main` and pull requests on the Linux Node matrix (22.23/24/26) and a Windows job (22.23.2). They include typecheck, lint, format:check, test, property test, coverage, build, the dist integration harness (`npm run integration:dist`) and smoke;
- a weekly scheduled job (also manually dispatchable) runs the blocking mutation gate (`break: 80`) and the large-count property suite.

Supplementary local enforcement: `scripts/quality-gate.sh` runs the same fast-gate sequence (opt-in `pre-push` hook via `scripts/install-hooks.sh`; full sequence also runs on `prepublishOnly`). The hook and the publish gate need `bash` on `PATH` (Git Bash on Windows). macOS is verified locally; Linux and Windows are covered by GitHub Actions.

## License

[MIT](LICENSE)

## AI Disclosure

The text in this README and the images included in it were generated with the assistance of artificial intelligence.
