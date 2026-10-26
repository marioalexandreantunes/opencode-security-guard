# OpenCode V2 migration

## Status and objective

Migration plan for `opencode-security-guard`, previously used with OpenCode `1.19.4`, targeting OpenCode `2.1.4`. The user reported that the plugin stopped working after upgrading. **This document neither implements nor certifies the migration.**

Research conducted on 26 October 2026 using the official V2 documentation and source code from tag `v2.1.4`, commit `68bc26b7da1990ce10ffecfbc1e09eb13aa5d824`. Public documentation may evolve; the specific contracts below were cross-checked against that tag. The supplementary Context7 lookup provided `v2.1.2`, not `v2.1.4`; it was not used alone to claim compatibility with `2.1.4`.

**Conclusion:** the plugin API introduced breaking changes. V2 does not run the V1 implementation. Updating configuration, copying the bundle again, or changing the dependency alone does not convert the hooks. [1][2]

## 1. Current repository implementation

| File | Current dependency or behavior |
| --- | --- |
| `package.json` | `@opencode-ai/plugin` pinned to `1.18.31` for peer and development dependencies; distinguish the SDK from runtime `1.19.4` |
| `src/index.ts` | Only the named `SecurityGuard` export; no default V2 definition |
| `src/plugin.ts` | Async factory receives `{ client, directory, worktree }` and returns a V1 hook map |
| `src/plugin.ts` | Types derived from `Hooks`, separate `input`/`output` arguments, correlation through `callID` |
| `src/plugin.ts` | Shell policy conditional on `tool === "bash"`; read blocking uses `args.filePath` |
| `src/tool-output.ts` | Recursive redaction and suppression on failure; fallback designed for V1 |
| `src/write-policy.ts` | Already recognizes `filePath`, `path`, and destinations in `patchText` |
| `tsup.config.ts` | ESM bundle from `src/index.ts`, with TypeScript declarations |
| `scripts/install-windows.ps1`, `scripts/install-mac.sh` | Global installation of a single `security-guard.js` file |
| `scripts/integration-dist.mjs`, `scripts/smoke-dist.mjs`, `tests/` | V1 contracts; integration harness requires exactly one named export |

Reuse the scanner, rules, blacklist, vault, and path policies. Adapt host integration without duplicating rules or introducing a generic framework. Review shared state and configuration read during module import.

## 2. Entrypoint, dependencies, and loading

### New entrypoint

The V2 entrypoint default-exports the result of `Plugin.define`, imported from `@opencode/plugin`, with: [2][5]

- A stable `id`, for example `opencode-security-guard`;
- `setup(ctx)` to initialize state and register hooks;
- A cleanup function returned by `setup`, replacing the `dispose` hook returned by the V1 factory.

In the inspected tag, `@opencode/plugin` declares version `2.1.4`. Prepare the corresponding dependency and lockfile when implementing the migration; verify actual publication and resolution before installing. Do not copy `workspace:*` fields from the upstream monorepo manifest. [4]

The current V1 import is type-only. `Plugin.define` introduces a runtime import: review `tsup` externalization, exports, generated declarations, and dependency resolution in the global installation. A bundle that works inside the repository may fail when copied without external dependencies. Do not retain the “zero runtime dependencies” claim without revalidation.

### V2 configuration

Configuration for an **already migrated plugin directory**, relative to the `opencode.json` file:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["./plugins/security-guard"]
}
```

That directory must provide a `server` or `index` module, for example `plugins/security-guard/index.js`, and resolve the required imports. Do not point V2 configuration directly at `file:///.../dist/security-guard.js`: configured local paths must identify directories; individual files are skipped with a warning. [2][3]

**Important distinction:** automatic discovery still accepts direct `.ts`/`.js` files in `.opencode/plugins/` and `~/.config/opencode/plugins/`. The installers' current destination can remain in use, but only with ported content and resolvable dependencies. Converting that discovered installation into a directory is not mandatory. Do not enable discovery and explicit configuration simultaneously. [3]

V2 normalizes supported V1 configuration but recommends `plugins` instead of `plugin`. This compatibility does not cover plugin implementation code. Keep a copy of the V1 configuration before converting fields. [1]

## 3. Hook mapping

| Current implementation | V2 destination | Adaptation |
| --- | --- | --- |
| `tool.execute.before` | `ctx.tool.hook("execute.before", ...)` | One event; arguments in `event.input`, not `output.args` |
| `tool.execute.after` | `ctx.tool.hook("execute.after", ...)` | Distinguish success/error; result in `event.result` |
| `chat.message` | `ctx.session.hook("prompt", ...)` | Text in `event.prompt.text`; admission before persistence |
| `experimental.chat.messages.transform` | `ctx.session.hook("context", ...)` | Traverse `event.messages`, now model messages |
| `experimental.chat.system.transform` | The same `context` hook | Traverse `event.system`, now structured parts |
| `dispose` | Cleanup returned by `setup` | Clear vault, blacklist, caches, and instance registration |

Also register request protection for `compaction`, `generate`, and `title`. `context` covers the main loop and tool-driven continuations, not every request a session issues. The `title` event has neither `agent` nor `tools`. [2][7]

### Before tool execution

Contracts confirmed in the `v2.1.4` source: [6][9]

| Operation | V2 shape | Impact on our code |
| --- | --- | --- |
| Shell | `shell` tool; `input.command`, `input.workdir`, `input.background` | The current `bash` branch no longer runs; apply policy to the V2 tool |
| Read | `read`; `input.path` | `args.filePath` misses the target; adapt `block` mode |
| Write | `write`; `input.path`, `input.content` | `writeTargets` already accepts `path`; validate the complete flow |
| Edit | `edit`; `input.path`, `oldString`, `newString`, `replaceAll` | Preserve surgical rehydration |
| Patch | `patch`; `input.patchText` | Validate additions, updates, deletions, and `Move to` |
| Correlation | `event.sessionID`, `event.messageID`, `event.id` | `event.id` identifies the call; map to `callID` only in our log schema |

`event.input` is `unknown`: validate its shape before accessing fields. Preserve rejection of uninspectable arguments and unknown markers. Do not use casts to hide incompatibilities.

Preserve the order: inspect arguments/destinations, block sensitive paths and worktree escapes, and only then restore known values in local input. Test that the modified input is actually executed and the restored secret does not reappear in the next model request.

The official guide demonstrates blocking by throwing in `execute.before`. Verify on the real host that the exception prevents execution and produces sanitized diagnostics; successful hook registration does not prove policy enforcement. [2]

`ctx.shell.hook("create.before", ...)` is also available, with `command`, `cwd`, `timeout`, `shell`, and `env`. Evaluate it as additional process-creation coverage without assuming equivalence to tool hooks: this event does not provide a `sessionID`/call ID. Avoid rehydrating twice. [10]

### After tool execution: success and error

The event is a discriminated union: [6][8]

- `status === "completed"`: `event.result` is a `Tool.Result`, with optional structured `output`, optional `content`, and optional `metadata`;
- `content` can be text or a list of `text`/`file` parts;
- `status === "error"`: `event.error` is a `Tool.Error`, with `message`, `error`, and `metadata`; there is no `event.result`.

Adapt `redactToolValue` to the entire result: `output` is not the only surface. Sanitize errors before model reuse, including messages and nested data serialized by the host.

The internal fields of `Tool.Result` are readonly in the contract. Prefer constructing a sanitized result and assigning it to the replaceable `event.result`; verify types and avoid relying on mutation of frozen objects.

Review `neutraliseOutput`: in V2, failure must replace the result with valid safe content, removing the original `output`, content, and metadata. Do not retain unsafe payloads in parallel fields. For errors, construct a sanitized representation compatible with `Tool.Error`, without preserving unsafe causes.

Binary attachments, images, and PDFs remain outside textual detection. Do not blindly rewrite URIs, base64, or opaque content: block/suppress where required by the stated policy and document remaining limitations.

### Prompt, history, and system

`prompt` runs once before durable admission. Changes become persisted input; it is not a filter before every model call. Synthetic messages and compaction controls do not pass through it. If redaction changes text length, update/remove attachment `mention` offsets. Files and skills are resolved only after this hook. [2][7]

In request hooks, the V1 `{ info, parts }` structure no longer applies: [11]

- `system` contains `{ type: "text", text, ... }` parts, not `string[]`;
- Messages have `role`, `content`, and optional `metadata`, `providerMetadata`, and `native` fields;
- `content` may include text, reasoning, calls with `input`, results with `result`, media, and compaction;
- Preserve IDs, roles, types, names, and namespaces required by the protocol; review `PART_SKIP`, `INFO_SKIP`, and `TOOL_SKIP` against V2 fixtures;
- Traverse textual fields sent to the provider, including locally rehydrated input from earlier calls.

Changes in these hooks affect the outgoing request, not persisted history. Redact every request; retain negative caching and invalidation when the blacklist changes. On inspection failure, require that no unsafe request is sent, testing the host's actual behavior.

**Coverage boundary:** the summary prompt is appended after the `compaction` hook; HTTP overlays can also change fields after semantic preparation. Later hooks may reintroduce secrets. Test the actual outgoing payload, not only objects observed by the plugin. HTTP hooks do not see WebSocket traffic; any final transport inspection requires specific coverage or an explicit limitation. [12]

## 4. Location, isolation, and lifecycle

Use `ctx.location.directory` and `ctx.location.project` metadata instead of expecting V1 `directory`/`worktree` arguments. The instance location is not necessarily the location of every observed session/event. [2][5]

Before choosing the root for `.security-guard/` and rehydration:

1. Confirm the session, active directory, and corresponding checkout/worktree.
2. Distinguish `project.directory` from `project.canonical`; do not broaden permissions to the canonical checkout when operating in a separate worktree.
3. Ensure isolation of the vault, blacklist, caches, logs, and duplicate-registration tracking.
4. Test two locations, location changes, and reloads.

`setup` must check `halt` before registering hooks. Its returned cleanup clears in-memory values and releases the instance identity, like the current `dispose`. Registrations are removed automatically on unload; owned resources still require cleanup. **Do not store secrets in `ctx.storage`**: unlike the vault, it is durable. [2]

Do not carry over `client.app.log` and `client.tui.showToast` without adaptation. V2 `ctx.app` exposes name, version, and channel, not `log`. Preserve sanitized local logs; treat notifications as a separate optional integration. A TUI extension requires the CLI plugin API, not a fallback between argument shapes of the old `showToast`. [5][13]

## 5. Proposed implementation sequence

1. **V1 baseline:** run gates and record results, identifying runtime `1.19.4` and SDK `1.18.31` separately.
2. **V2 entrypoint:** for example `src/opencode-v2.ts` and a separate bundle. Initially preserve `src/index.ts` and the V1 installation; reuse only necessary logic. These are proposed names that do not exist yet.
3. **Tools:** migrate `shell`, `path`, `event.input`, `event.id`, results, and errors; test before re-enabling rehydration.
4. **Inference:** migrate prompt admission and all four request kinds, using V2 structures and fail-closed behavior.
5. **Lifecycle:** location, isolation, `halt`, logs, and cleanup.
6. **Distribution:** dependencies, exports, build, and installers; only one active installation in the V2 environment.
7. **V2 harness:** capture registrations during `setup`, events, and cleanup; do not reuse a V1 hook map as though it were a V2 host.
8. **Real runtime:** validate OpenCode `2.1.4`, the bundle installed outside the repository, a test endpoint without real credentials, and Windows/Linux. Update the README only with demonstrated compatibility.

Dual support is possible through a default export containing V1 `server()` and V2 `setup()`. The guide places V1 object-entrypoint support at `1.18.29` or newer. This is an alternative, not automatic conversion; it requires tests on `1.19.4` and `2.1.4`, including the effect of the V2 import on V1 loading. Introducing this coupling is not required to complete the initial migration. [2]

## 6. Acceptance criteria

Use only synthetic canaries generated in memory. Never use real credentials.

| Test | Required result |
| --- | --- |
| Loading | Correct ID in `opencode plugin list`; no invalid-entry/missing-dependency warnings |
| Prompt and resolved attachments | No canary in the outgoing request; valid references |
| History, system, and metadata | Outgoing textual surfaces redacted without breaking the protocol |
| `context`, `compaction`, `generate`, `title` | Flows tested separately, including continuations and summaries |
| V2 tools | `shell`, `read.path`, `write.path`, `edit.path`, and `patch.patchText` actually inspected |
| Results and failures | Canaries absent from `content`, `output`, `metadata`, and serialized errors |
| Redactor failure/limits | Unsafe result suppressed or request prevented; no plaintext |
| Blocking | Prohibited operation not executed even when normal permissions are `allow` |
| Rehydration | Correct value only in local execution; absent from logs, the next request, and replay |
| Invalid inputs/destinations | Unknown markers, uninspectable arguments, external destinations, and symlink/junction escapes blocked according to policy |
| Background shell | Synthetic notification and later result remain safe at inference |
| Locations and reload | No vault/log/blacklist mixing, duplicate hooks, or vault reuse after cleanup |
| `halt` and variables | No hooks when disabled; modes and options preserved |
| Distribution | Bundle loads without accidentally depending on the repository's `node_modules` |
| Transports | Actual payload verified on supported transports; explicit HTTP/WebSocket limitations |

Run existing gates after adapting tests and build:

```sh
npm run typecheck
npm run lint
npm run format:check
npm test
npm run test:property
npm run coverage
npm run build
npm run integration:dist
npm run smoke:dist
```

These commands currently validate the V1 integration. They count as V2 evidence only after adding V2 cases/an entrypoint. A simulated harness does not replace testing runtime `2.1.4` or prove by itself that secrets are absent from the final transport payload.

For diagnostics, use `opencode service status`, `opencode plugin list`, and the service log, redacting sensitive content. Use `/reload` to force a reload; watched configuration/plugin changes reload automatically. Do not rely on restarting for ordinary configuration changes. [3][14]

## 7. Outstanding work before declaring support

- Implement/test the V2 entrypoint and distributed dependency resolution.
- Confirm root selection/isolation in worktrees and moved sessions.
- Demonstrate exception-based blocking and safe error suppression on the real host.
- Demonstrate protection of auxiliary requests, synthetic messages, and transports.
- Decide on V2 notifications and whether to retain V1 support.

No dependencies were installed and no V2 runtime tests were executed while preparing this document. The configuration example describes a future migrated installation; it does not make the current bundle compatible.

## Sources

1. [Official V1 → V2 migration guide](https://opencode.ai/v2/docs/migrate-v1).
2. [Plugin API migration](https://opencode.ai/v2/docs/build/plugins/migrate-v1) and [v2.1.4 source](https://github.com/anomalyco/opencode/blob/v2.1.4/services/www/src/docs/content/build/plugins/migrate-v1.mdx).
3. [V2 plugin configuration, discovery, and management](https://opencode.ai/v2/docs/plugins).
4. [@opencode/plugin v2.1.4 manifest](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/plugin/package.json).
5. [Plugin.Context, setup, and cleanup in v2.1.4](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/plugin/src/promise/plugin.ts).
6. [Tool events in v2.1.4](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/plugin/src/promise/tool.ts).
7. [Session events in v2.1.4](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/plugin/src/promise/session.ts).
8. [Tool.Result, Tool.Content, and Tool.Error in v2.1.4](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/schema/src/tool.ts).
9. Tools in v2.1.4: [shell](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/core/src/tool/plugin/shell.ts), [read](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/core/src/tool/plugin/read.ts), [write](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/core/src/tool/plugin/write.ts), [edit](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/core/src/tool/plugin/edit.ts), [patch](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/core/src/tool/plugin/patch.ts).
10. [ShellCreateBefore v2.1.4](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/plugin/src/promise/shell.ts).
11. [Messages and system parts in v2.1.4](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/ai/src/schema/messages.ts).
12. [Complete guide: request hooks and transports](https://opencode.ai/v2/docs/build/plugins).
13. [App v2.1.4](https://github.com/anomalyco/opencode/blob/v2.1.4/packages/plugin/src/app.ts) and [CLI plugins](https://opencode.ai/v2/docs/build/plugins/cli).
14. [V2 troubleshooting](https://opencode.ai/v2/docs/troubleshooting).

---

**AI disclosure:** This document was produced by artificial intelligence.
