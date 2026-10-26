# OpenAI Codex plugin migration plan

## Status and objective

Planning only. No Codex plugin has been implemented or runtime-tested here.

Adapt this repository's OpenCode security guard to the OpenAI Codex agent,
starting with local Codex CLI on Windows. Preserve the existing OpenCode entry
point and reuse the secret scanner and policy modules wherever their contracts
fit Codex. Treat the Pi plan in `docs\Harnesses\Pi.md` as a separate host integration.

Documentation rechecked on 2026-10-13. Discovery did not find `codex` on the
current `PATH`; this does not rule out another installation location. The
installed version and runtime behavior remain unverified. Identify a specific
release before implementing or claiming support, and record its Windows shell,
provider, enabled plugins, hook sources, and trust configuration.

## Official documentation and scope

User-provided starting reference:
https://developers.openai.com/learn/developers-codex-plugin

This page describes the **OpenAI Developers plugin** and its installation and
capabilities. It is an example of a Codex plugin, not the complete API contract
for building a security enforcement plugin. Use the official hooks and plugin
documentation listed under References for the actual integration contracts.

The reviewed documentation supports plugin-bundled hooks through
`.codex-plugin/plugin.json` and, by default, `hooks/hooks.json`. Hooks can invoke
commands or already-connected MCP tools. Command hooks receive JSON on standard
input and return event-specific decisions through standard output and exit codes.
This differs from an in-process OpenCode JavaScript plugin.

Initial scope is local CLI. Evaluate desktop separately. The reviewed plugin
documentation says the IDE extension does not support plugins and local plugin
hooks do not run in cloud-orchestrated ChatGPT Work. Do not infer coverage across
all Codex or ChatGPT surfaces from a local CLI test.

## Documented capabilities and runtime validation gaps

| Existing OpenCode behavior | Codex candidate | Documented constraint |
| --- | --- | --- |
| Pre-execution tool policy | `PreToolUse` | Explicit denial blocks supported local tool paths |
| Argument restoration | `PreToolUse` with `updatedInput` | Requires `permissionDecision: "allow"`; validate approval interaction |
| Tool-output protection | `PostToolUse` | Blocking feedback can replace the model-facing result; cannot undo side effects |
| Exact structured-result redaction | No direct equivalent established | `updatedMCPToolOutput` is parsed but not supported |
| User message protection | `UserPromptSubmit` | Can reject a prompt; no documented replacement of the original prompt |
| Full history and system transformation | No global hook established in reviewed contracts | Extra context does not remove secrets already present |
| Session cleanup | `SessionStart`, `SessionEnd`, subagent events | Main-thread and subagent lifecycle differ; command processes are separate |
| Toasts and logs | Sanitized `systemMessage`, standard error, existing log sink | Hook output and additional context may be displayed or stored |

### Tool coverage

- Shell and unified execution match `Bash`; `apply_patch` also matches `Edit` or `Write`.
- MCP and other local function tools have pre/post hooks; inspect their actual schemas.
- Hosted tools such as web search do not use the documented local function-tool hook path.
- Some specialized tools can opt out; hooks are not a complete enforcement boundary.
- `write_stdin` does not run `PreToolUse` again for an existing execution session.
- Code-mode nested calls have documented hook behavior, but need integration tests.

### Decisions are not interchangeable between events

- `PreToolUse`: use explicit denial or the documented blocking exit code, not `continue: false`.
- `PostToolUse`: blocking feedback replaces the result; code-mode nested promises may reject.
- `UserPromptSubmit`: rejection is supported; adding sanitized context does not sanitize the original prompt.
- `Stop`: `decision: "block"` asks for continuation; it is not a security denial.
- `SubagentStart`: `continue: false` does not stop the subagent.

Unsupported fields, malformed responses, timeouts, and hook errors can allow
processing to continue. MCP-hook connection failures explicitly do not block
operations. An explicit successful denial is different from a crashed hook.
Do not label this integration fail-closed until the target runtime proves it.

### Required scope and failure decisions

Decide before phase 2 whether full OpenCode parity is required or an explicitly
accepted restricted capability prototype is sufficient. The reviewed contracts
do not establish transparent prompt replacement, global history/system redaction,
or lossless structured-result rewriting. Missing mandatory boundaries are
blockers, not successful migration results.

Matching command hooks run concurrently and receive the original event data.
The guard cannot sanitize that data before another matching hook starts. Test
all enabled hook sources and plugins, including competing input rewrites and
model-visible additional context; sanitizing the guard's own response is not a
global sanitization boundary.

For catchable scanner/input-processing failures, return the event's documented
blocking response or exit code with a fixed sanitized reason. A launch failure,
uncaught crash, timeout, disabled hook, or unavailable MCP server is a different
failure mode and can permit continuation. Prove each advertised failure guarantee
separately and document any explicitly accepted limitation.

For code-mode confidentiality, use the validated `PostToolUse` blocking decision
or blocking exit code. `continue: false` can replace model-facing feedback while
still resolving a nested tool promise with the original result; it is not an
equivalent protection for the running script.

## Proposed implementation boundary

Reuse TypeScript sources rather than editing the deployed OpenCode bundle.

| Existing source | Intended reuse |
| --- | --- |
| `src/rules.ts` | Detection, fingerprints, encoded-secret scanning |
| `src/redact.ts`, `src/tool-output.ts` | Redaction helpers where output contracts permit |
| `src/paths.ts`, `src/bash.ts` | Sensitive-path and shell-command policies |
| `src/write-policy.ts` | Canonical destination and project-boundary checks |
| `src/blacklist.ts` | Blacklist parsing and refresh |
| `src/config.ts`, `src/project-dir.ts` | Sanitized logs, environment options, project-local state |
| `src/vault.ts` | Restoration semantics; lifecycle cannot be copied unchanged |
| `src/plugin.ts` | Existing orchestration to extract only when genuinely shared |

Start with a small Node.js command entry point, provisionally
`src/codex-hook.ts`, and a Codex plugin directory containing the manifest,
hook configuration, and packaged command artifact. Final layout and distribution
metadata remain implementation decisions. Avoid copying detector rules or
introducing a general-purpose adapter framework.

### Vault decision

Separate command-hook invocations do not share this plugin's in-memory vault or
process HMAC key. A marker captured in one process cannot automatically be
restored in another. Decide explicitly between:

1. An initial restricted adapter without cross-invocation restoration, clearly documenting the lost capability.
2. A session-scoped local service that owns the vault and fingerprints, with authenticated IPC and strict lifecycle isolation.

Prefer the first option for a capability prototype. Do not add a service until
restoration is required and supported input/output boundaries are proven. Do not
persist plaintext secrets in hook payloads, transcripts, or plugin data files
to simulate an in-memory vault. Record any long-term architecture decision using
the repository's decision-documentation workflow.

Without shared restoration state, explicitly block marker-bearing writes and
edits rather than writing placeholders. Preserve the existing inspection policy
for full rewrites of secret-bearing or unverifiable files when restoration is
disabled. The current vault uses LRU eviction and explicit clearing, not a TTL;
process-local fingerprints are not stable cross-invocation identifiers.

## Migration phases

### 1. Establish baseline and runtime contracts

- [ ] Read `AGENTS.md`, `docs/QualityContract.md`, existing tests, and build configuration.
- [ ] Run existing quality gates and record the OpenCode baseline.
- [ ] Identify Codex version, execution surface, Windows shell, and hook feature configuration.
- [ ] Record the initial provider, fixed plugin/hook configuration, trust state, and required protection scope without recording credentials.
- [ ] Inspect that release's hook schemas, matcher aliases, trust behavior, and tool coverage.
- [ ] Inventory shell/unified execution, patches, MCP file/search tools, hosted tools, and interactive execution sessions; distinguish matcher aliases from actual tool input schemas.
- [ ] Build a coverage matrix for input, tool calls, results, history, system content, hosted tools, and subagents.
- [ ] Reproduce denial, rewrite, timeout, malformed-response, and hook-crash behavior in a disposable workspace.

Deliverable: capability evidence and a go/no-go decision for each protection
claim. Distinguish enforced protection, best-effort checks, and uncovered paths.

#### Mandatory feasibility gate before phase 2

- [ ] Establish the release-specific contracts in a disposable workspace; documentation or generated protocol JSON alone is insufficient.
- [ ] Prove explicit denial prevents the underlying operation and secret-bearing prompts are rejected before a captured model request.
- [ ] Prove sensitive-result blocking prevents original output from reaching the model and, where claimed, nested code-mode callers; include streaming and polling results.
- [ ] Inject catchable scanner failures, launch failures, crashes, timeouts, malformed/unsupported responses, and missing MCP connections; record which cases block and which continue.
- [ ] Test concurrent hooks and conflicting rewrites/additional context; identify channels that can reintroduce or receive secrets outside the guard.
- [ ] Select restoration scope. If enabled, prove cross-invocation state, `updatedInput` semantics, and approval behavior without persisting plaintext secrets. Otherwise prove safe marker/write rejection.
- [ ] Record whether final-request, history, system, and structured-result guarantees are achievable. Obtain explicit acceptance of any restricted prototype scope before proceeding.

Proceed to phase 2 only when every required claim has passing runtime evidence.
If full parity is required and a necessary boundary is unavailable, mark the
migration BLOCKED. Do not reinterpret unsupported hooks or fail-open cases as
passing enforcement, or patch private runtime internals to bypass the gate.

### 2. Package a minimal command-hook adapter

- [ ] Add the Node.js hook entry point with bounded JSON input and event-specific validation.
- [ ] Keep standard output exclusively for valid hook protocol responses; sanitize diagnostics.
- [ ] Bound hook response size and sanitize reasons, standard error, `systemMessage`, and additional context before Codex can display, persist, or spill them to disk.
- [ ] Package `.codex-plugin/plugin.json` and `hooks/hooks.json` using the tested schema.
- [ ] Resolve executable paths from the plugin root; do not depend on session `cwd` being the repository root.
- [ ] Provide tested Windows command resolution and quoting, using `commandWindows` where needed.
- [ ] Reuse existing policy modules and preserve the OpenCode export/build contract.
- [ ] Verify current versions before introducing dependencies; select a tested compatibility range.

### 3. Implement pre-execution policy

- [ ] Map canonical tool names and schemas to existing path and shell checks.
- [ ] Map Windows PowerShell and other shell execution through the actual `Bash` matcher/input contract; do not assume an OpenCode `tool === "bash"` check covers Codex tool names.
- [ ] Inspect `tool_input.command` for `Bash` and `apply_patch`; inspect JSON arguments for other tools.
- [ ] Deny prohibited calls before underlying execution; include sanitized reasons only.
- [ ] Validate patch destinations, moves, deletes, symlinks, missing paths, and Windows path variants.
- [ ] Test shell escalation, approvals, long-running sessions, and `write_stdin` coverage gaps.
- [ ] If restoration is selected, verify rewritten arguments and project-boundary policy with the chosen vault design.
- [ ] Without restoration, block markers in writes/edits and safely inspect existing full-rewrite targets; test unknown markers, absent state, and unverifiable files.
- [ ] Preserve mode semantics: sensitive reads block in `SECURITY_GUARD_MODE=block`; in `redact`, prove replacement of model-visible results for covered read paths.
- [ ] Test concurrent hooks and calls; do not assume a policy hook prevents other hooks from starting.

Use synchronous hooks for enforcement. Background hooks cannot block or rewrite
the operation that triggered them. Avoid automatic approval behavior unless the
tested restoration contract requires it and its consequences are documented.

### 4. Implement achievable input/output protection

- [ ] Reject user prompts containing prohibited secrets through `UserPromptSubmit`.
- [ ] Test whether sensitive tool results can be safely replaced with sanitized feedback before model consumption.
- [ ] Preserve clean results unchanged; document structural loss when replacing secret-bearing results.
- [ ] Handle errors and encoded-secret cases without leaking original content through reasons or additional context.
- [ ] Convert catchable scanner failures into the validated event-specific denial/block response; keep host launch/crash/timeout limitations explicit.
- [ ] Test streaming and partial outputs, unified-exec polling, code mode, and structured MCP results.
- [ ] Use blocking decisions or blocking exit codes when nested code must not receive original results; do not substitute `continue: false` for that guarantee.
- [ ] Determine what reaches UI, transcripts, temporary spill files, and other hooks before replacement.
- [ ] Establish whether any supported API covers final requests, history, and system content; record absence explicitly.
- [ ] Revalidate the fixed plugin/hook configuration if another hook injects content or rewrites input; do not claim a final-request boundary from pre/post hooks alone.

Do not advertise transparent prompt rewriting or global inference redaction
unless an actual supported interface and end-to-end tests establish them.
If full OpenCode parity is mandatory and these boundaries remain unavailable,
record a blocker and require a separate design decision instead of silently
reducing protection or modifying private runtime internals.

### 5. Integrate lifecycle, trust, and external tools

- [ ] Verify hook review/trust using `/hooks`; installation does not automatically trust plugin hooks.
- [ ] Test disabled hooks, changed definition hashes, untrusted projects, and managed-policy restrictions.
- [ ] Verify project isolation, blacklist refresh, halt behavior, sanitized logs, and duplicate registration.
- [ ] Test parent/subagent tool calls and lifecycle using actual agent identifiers, not only parent session IDs.
- [ ] Test MCP proxy/nested calls and any chosen local vault service; verify missing-service behavior.
- [ ] Test resume, compaction, interruption, normal exit, and abnormal termination.
- [ ] Document hosted-tool and subprocess blind spots and surface-specific support.
- [ ] Repeat denial, failure-injection, and model-request tests with all supported hooks/plugins enabled; configuration or release changes require renewed acceptance evidence.

### 6. Validate and distribute

- [ ] Add command-protocol unit tests, packaged-artifact smoke tests, and real Codex integration tests.
- [ ] Run unchanged OpenCode regression gates and compare shared-module behavior.
- [ ] Install from a local plugin/marketplace setup using the tested Codex release's documented workflow.
- [ ] Start a new session and verify hooks are loaded, trusted, and actually invoked.
- [ ] Document installation, runtime requirements, tested versions, protection scope, and troubleshooting.
- [ ] Publish only after acceptance evidence establishes each advertised guarantee.

## Acceptance scenarios

Use synthetic secrets assembled at runtime, never real credentials. Use
`<MARKER:…>` notation in documentation and build test markers from `MARKER`.
Fixtures must use temporary logs and project state configured before imports.

| Scenario | Observable success criterion |
| --- | --- |
| Clean prompt and tool result | Original content and protocol remain unchanged |
| Secret-bearing prompt | Rejected before a captured model request; reason is sanitized |
| Sensitive read with `SECURITY_GUARD_MODE=block` | Underlying covered read is never invoked |
| Sensitive read with `SECURITY_GUARD_MODE=redact` | Read may execute; captured model request contains no fixture secret through the validated result-replacement path |
| Sensitive write/patch or prohibited shell command | Underlying operation is never invoked |
| Sensitive output | Captured model request contains no fixture secret; replacement behavior is recorded |
| MCP structured result | No claim of unsupported structured rewriting; actual replacement semantics tested |
| Streaming/code mode/polling/`write_stdin` | Each channel's interception and leakage behavior recorded; blocking prevents original results reaching nested scripts where claimed |
| Catchable scanner failure | Validated event-specific block response; no original sensitive content or plaintext diagnostic in claimed channels |
| Hook launch failure/crash/timeout/malformed response or unavailable MCP hook | Actual continuation/blocking behavior reproduced; fail-open cases are explicit limitations, not fail-closed passes |
| Concurrent hooks and competing rewrites/context | No sequential-order assumption; exposure to other hooks and reintroduction paths recorded and required guarantees proven |
| Known/unknown marker or absent/evicted/cleared vault state | Chosen restoration scope works; missing state cannot fabricate a secret; restricted adapter rejects marker-bearing writes |
| Restoration-disabled full rewrite | Existing secret-bearing or unverifiable target is protected by the existing inspection policy |
| Resume/subagents/project switch | No unintended vault or fingerprint ownership across scopes |
| Disabled/untrusted hooks | Protection state reported accurately; no false claim of active enforcement |
| Logs/transcripts/spill files and oversized hook feedback | No plaintext fixtures in channels covered by the stated guarantee; hook responses are sanitized before host persistence |
| OpenCode regression | Existing public entry point and behavior remain compatible |

Use failing tests before implementing new behavior. A unit test of a generated
hook response does not prove the host consumes it before an inference request.
Capture actual requests with a controlled test transport where possible.

## Verification gates and completion

During implementation, use the existing repository gates matching
`scripts/quality-gate.sh`:

- `npm run typecheck`
- `npm run lint`
- `npm run format:check`
- `npm audit --audit-level=high`
- `npm test`
- `npm run test:property`
- `npm run coverage`
- `npm run build`
- `npm run integration:dist`
- `npm run smoke:dist`

Add Codex-specific protocol, package, and integration gates when their artifacts
exist. Apply `docs/QualityContract.md` coverage thresholds (lines >= 90%, branches
>= 85%) without global regression and record actual coverage results. Missing
required checks are BLOCKED unless an exception is approved. Follow `AGENTS.md`
for scoped mutation testing and temporary cleanup.

Completion requires the phase-1 feasibility gate, a tested package, proven denial
with no prohibited side effects, proven protection for every claimed model-visible
channel, explicit restoration scope, lifecycle/trust evidence, passing OpenCode
gates, and a
documented coverage matrix for the recorded release, provider, hook/plugin
configuration, and accepted scope. A restricted prototype is not full OpenCode
parity, and a working installation is not proof of protection.

## Decisions and their deadlines

1. Before phase 2: identify the Codex release, local Windows CLI surface, provider, enabled hook/plugin sources, and trust configuration.
2. Before phase 2: select full parity or an explicitly accepted restricted prototype; unresolved mandatory history/system/final-request boundaries are blockers.
3. Before phase 2: define failure guarantees and accepted launch/crash/timeout/MCP limitations using reproduced host behavior.
4. Before phase 2: choose no cross-invocation restoration or a separately justified session service; validate write safety and any `updatedInput`/approval consequences.
5. In phase 1: define streaming, interactive shell, code-mode, hosted-tool, other-hook, UI, persistence, and subagent coverage; validate each claim in the relevant phase.
6. After local acceptance: decide distribution layout and any additional surfaces or releases; require fresh evidence before widening support.

## References

- User-provided OpenAI Developers plugin guide: https://developers.openai.com/learn/developers-codex-plugin
- Official Codex plugin documentation: https://developers.openai.com/codex/plugins
- Official Codex hook documentation: https://developers.openai.com/codex/hooks
- Current canonical hooks page returned during research: https://learn.chatgpt.com/docs/hooks.md
- Codex source and release-specific contracts: https://github.com/openai/codex
- Repository guidance: `AGENTS.md`, `docs/QualityContract.md`, `README.md`, `SECURITY.md`, `scripts/quality-gate.sh`
- Related host plan: `docs/Harnesses/Pi.md`

These links describe evolving contracts. Re-check the installed release before
implementation; document the version and evidence instead of assuming upstream
main matches the user's Codex installation.

---

**AI disclosure:** This document was produced by artificial intelligence.
