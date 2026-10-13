# Pi extension migration plan

## Status and objective

Planning only. No Pi extension has been implemented or validated by this document.

Adapt the existing OpenCode security guard to Pi while preserving secret detection,
redaction before inference, access restrictions, controlled secret restoration,
blacklist support, and sanitized logging. Keep the OpenCode entry point compatible.

Initial target: Pi CLI 1.1.0 on Windows. The current installation uses
`pi-mcp-adapter` 5.2.0, `context-mode`, `pi-subagents`, and `@bacnh85/pi-rtk`.
Start with the installed DeepSeek configuration and a fixed extension set whose
exact versions and handler order are recorded and validated. Other Pi versions,
providers, or extension configurations require their own acceptance evidence.
Current upstream documentation alone does not prove compatibility with the
installed version.

## Existing implementation

The deployed OpenCode bundle is
`C:\Users\%USER%\.config\opencode\plugins\security-guard.js`.
Use this repository's TypeScript sources for implementation, not a fork of the
generated bundle.

| Source | Responsibility |
| --- | --- |
| `src/plugin.ts` | OpenCode hooks, orchestration, counters, restoration policy |
| `src/rules.ts` | Secret detection, fingerprints, encoded-secret scanning, cache |
| `src/redact.ts`, `src/tool-output.ts` | Recursive redaction and failure handling |
| `src/paths.ts`, `src/bash.ts` | Sensitive paths and shell-command checks |
| `src/write-policy.ts` | Canonical paths and project-boundary checks |
| `src/vault.ts` | Bounded in-memory storage for secret restoration |
| `src/blacklist.ts` | Project blacklist and refresh behavior |
| `src/config.ts`, `src/project-dir.ts` | Configuration, logs, project-local state |

Existing behavior includes optional `.security-guard/` bootstrap, `blacklist`,
`halt`, environment-controlled policies, log rotation, and bounded caches.
Some modules contain OpenCode-specific defaults or shared process state; audit
these before treating them as host-independent.

## Proposed implementation boundary

Add a Pi-specific TypeScript entry point, provisionally `src/pi.ts`, exporting
the default extension factory expected by Pi. Keep `src/index.ts` and the
OpenCode export contract intact.

Reuse existing detection and policy modules. Extract orchestration from
`src/plugin.ts` only when both adapters actually need it. Avoid copying rules,
introducing a general plugin framework, or adding unrelated policy features.

Build a separate Pi artifact, provisionally `dist/pi-security-guard.js`.
Decide package exports and Pi package metadata after the local adapter works.
If this becomes a long-term architectural choice, record the decision using
the repository's decision-documentation workflow.

## Hook mapping and contract verification

The following mappings are implementation candidates. Verify their exact types,
execution order, error behavior, and coverage against Pi 1.1.0 before coding.

| OpenCode integration | Pi integration candidate | Required proof |
| --- | --- | --- |
| `tool.execute.before` | `tool_call` | Block before execution; mutate `event.input` in place and prove restored arguments reach execution |
| `tool.execute.after` | `tool_result` | Replace model-visible text and structured results, including errors |
| `chat.message` | `input` | Transform user text without corrupting non-text content |
| `experimental.chat.messages.transform` | `context` / `context_with_system` plus final request validation | Cover resumed history, injected messages, and repeated inference calls |
| `experimental.chat.system.transform` | `context_with_system`, with `before_agent_start` where needed, plus `before_provider_request` | Cover the final system content actually sent to the provider |
| OpenCode toast/log client | Pi UI notifications and existing sanitized log sink | No secrets in notices or diagnostics; support non-interactive sessions |
| Plugin `dispose` | Pi lifecycle events, including `session_shutdown` | Clear state on shutdown, reload, and session/project transitions |

### Installed-runtime findings and feasibility risks

Review on 2026-10-13 confirmed the installed Pi version as 1.1.0. Inspection and
isolated dispatcher experiments established the following contracts; they do not
constitute end-to-end guard or DeepSeek transport validation:

- `tool_call` supports in-place mutation of `event.input`. Prove separately that
  the underlying tool receives the restored arguments without exposing them to
  inference.
- `context` excludes system messages, which Pi restores after each handler.
  `context_with_system` runs afterward with the full transcript. Evaluate it as
  the main request-local redaction layer, preserving the leading system message
  and tool protocol, with provider-request verification as a separate layer.
- The dispatcher catches handler exceptions in `tool_result`, `context`,
  `context_with_system`, and `before_provider_request` and continues. Experiments
  confirmed that throwing from `tool_result` or `before_provider_request` can
  retain original content. A thrown scanner error is not a fail-closed strategy.
- A later `before_provider_request` handler can replace an already sanitized
  payload. The event name does not guarantee that the guard runs last.

Pi's `before_provider_request` can replace a provider payload. Its payload is
provider-specific: do not redact every string indiscriminately. Preserve model
identifiers, tool names, schemas, references, and other protocol fields. Identify
the content-bearing fields for every supported provider and verify the final
request with a fake transport.

Define a supported safe replacement or cancellation path for scanner/transform
failures and prove that original sensitive content never reaches the transport.
Record effective handler order, including registrations made after initial
loading. If a later handler can reintroduce sensitive content without a further
validated boundary, that configuration cannot claim final-request protection.

Pi's `user_bash` event handles `!` and `!!` separately from model tool calls.
It returns custom operations or a replacement result, not the `tool_call`
blocking object. Include this path explicitly in the coverage decision.

## Migration phases

### 1. Establish baseline and security boundaries

- [ ] Read `AGENTS.md`, `docs/QualityContract.md`, existing security tests, and build configuration.
- [ ] Run current quality gates and record baseline results before changing shared code.
- [ ] Inspect installed Pi types and runtime dispatch for each proposed event.
- [ ] Inventory Pi tool names and input fields: `read`, `write`, `edit`, `bash`, `powershell`, `grep`, `find`, `ls`, and extension tools; decide access-policy coverage for each.
- [ ] Record the DeepSeek provider/API configuration, exact extension versions, and effective handler order without recording credentials.
- [ ] Identify provider-bound content, local session persistence, UI output, and direct subprocess paths.
- [ ] Record which paths are covered, uncovered, or require an integration experiment.

Deliverable: a versioned hook/coverage matrix with observable acceptance scenarios.
Do not claim full protection based only on successful extension loading.

#### Mandatory feasibility gate before phase 2

- [ ] Inject scanner/transform failures into the proposed result and request handlers; prove a safe replacement or supported cancellation prevents original sensitive content from reaching the provider, with sanitized diagnostics.
- [ ] Register a later handler that reintroduces fixture content; prove the final transport boundary remains protected under the documented extension configuration and order.
- [ ] Verify the proposed `context_with_system` transformation preserves the leading system message, tool declarations, and call/result correlation.
- [ ] Prove that `tool_call` mutation reaches the underlying write/edit operation and that prohibited calls never invoke it; use a narrow supported wrapper only if this proof fails.
- [ ] Record commands, versions, outcomes, and coverage limits for these experiments.

Proceed to phase 2 only when these proofs pass for the initial configuration.
If safe failure or final-boundary ordering cannot be established using supported
APIs, mark the migration BLOCKED and revise the scope or integration design
before implementing shared-engine changes.

### 2. Implement lifecycle and shared-engine integration

- [ ] Add the Pi default export and initialize project scope from Pi's actual working directory.
- [ ] Reuse scanners, blacklist, vault, and canonical-path policy.
- [ ] Map notifications without requiring OpenCode's `client` object.
- [ ] Preserve documented `SECURITY_GUARD_*` behavior; distinguish Pi logs where necessary.
- [ ] Define vault ownership across new sessions, resume, fork, reload, and project changes.
- [ ] Clear sensitive state at the appropriate lifecycle boundaries; prevent cross-project restoration.
- [ ] Keep fixtures hermetic: set temporary log and project-state paths before module imports.

### 3. Implement pre-execution protection and restoration

- [ ] Apply existing sensitive-path and shell policies to Pi's actual argument schema.
- [ ] Apply and verify shell protection for both `bash` and `powershell`; the current OpenCode adapter only dispatches shell checks for `tool === "bash"`.
- [ ] Enforce or explicitly exclude access restrictions for `grep`, `find`, and `ls` according to the coverage matrix; result redaction alone does not prove access was blocked.
- [ ] Reject prohibited calls before any filesystem, shell, or network side effect.
- [ ] Restore known markers only for permitted operations and destinations.
- [ ] Test Pi `edit` using the installed `edits[].oldText/newText` schema: restore markers in both fields, cover multiple replacements, preserve exact matching, and prevent unintended secret overwrites.
- [ ] Preserve existing behavior for unknown markers, disabled restoration, external paths, and failures.
- [ ] Check canonical destinations, symlinks, missing targets, and Windows path variants.
- [ ] Handle user shell execution with its own event contract and explicit `!`/`!!` policy.

If Pi cannot safely modify arguments in a pre-execution hook, investigate a
supported tool wrapper for the affected tool. Do not silently drop restoration
or patch private Pi internals.

### 4. Implement redaction before inference

- [ ] Sanitize tool text, structured content, and error results before model consumption.
- [ ] Transform user input and model context using supported Pi events, including full-transcript redaction through `context_with_system` where validated.
- [ ] Validate final provider requests after other extensions have injected content, using the configuration and handler order proven in phase 1.
- [ ] Preserve message roles, tool-call correlation, non-text blocks, and protocol metadata.
- [ ] Implement the safe replacement or cancellation proven in phase 1 for scanner/transform errors; do not rely on exceptions swallowed by Pi's dispatcher.
- [ ] Recheck event ordering when later handlers modify a previously sanitized payload or registrations change after loading.
- [ ] Test compaction, resumed sessions, prompt templates, skills, and system instructions.

State the scope precisely: inference redaction does not automatically sanitize
existing session files, streaming UI previews, attachments, or subprocess logs.
Prove each guarantee separately; document uncovered channels.

### 5. Verify extension and MCP interactions

- [ ] Test directly exposed MCP tools and `pi-mcp-adapter` proxy execution.
- [ ] Test `context-mode` execution/file processing and their model-visible output.
- [ ] Determine whether nested MCP calls bypass Pi's outer `tool_call` event.
- [ ] Verify whether `pi-subagents` child processes load the guard and whether parent results are sanitized.
- [ ] Test `@bacnh85/pi-rtk` and result-transform ordering with the guard enabled.
- [ ] Document any supported configuration requirements and remaining blind spots.
- [ ] Repeat final-boundary and failure-injection tests with the fixed extension set enabled; changing versions or handler order requires renewed acceptance evidence.

Sanitizing an outer proxy result does not prove that inner calls were blocked or
their arguments protected. Child processes do not automatically inherit hooks
or the in-memory vault. Unknown nested operations need an explicit coverage
decision; avoid describing the extension as a sandbox.

### 6. Package, install, and document

- [ ] Extend the build with the Pi artifact and a dedicated import smoke test.
- [ ] Use Pi SDK types compatible with the tested release; keep runtime host dependencies external where required.
- [ ] Before adding dependencies, verify current versions and select a tested compatibility range.
- [ ] Start with a local install under `C:\Users\Antunes\.pi\agent\extensions\`.
- [ ] Verify extension discovery, default export, restart/reload behavior, and duplicate-load prevention.
- [ ] Confirm existing OpenCode consumers still import and execute the original bundle.
- [ ] Document installation, supported versions/providers, environment options, logs, and limitations.
- [ ] Decide distribution metadata only after local end-to-end acceptance passes.

## Acceptance tests

Use synthetic fixtures assembled at runtime. Never use real credentials or emit
the guard's concrete marker literal in documentation or tool commands; use
`<MARKER:…>` notation and construct test markers from `MARKER`.

| Scenario | Observable success criterion |
| --- | --- |
| Clean input/output | Content and tool protocol remain unchanged |
| Secrets in user input, system content, tool results, history | Captured provider request contains no fixture secret |
| Structured/error output and encoded credentials | Existing scanner rules apply without breaking result structure |
| Sensitive read with `SECURITY_GUARD_MODE=block` | Underlying read is never invoked |
| Sensitive read with `SECURITY_GUARD_MODE=redact` | Read may execute; model-visible output is sanitized and the captured provider request contains no fixture secret |
| Sensitive write/edit or prohibited `bash`/`powershell` command | Underlying operation is never invoked |
| `grep`, `find`, `ls`, and extension-tool access | Every claimed restriction prevents the underlying access; uncovered operations are explicitly recorded |
| Known marker in permitted write/edit | Original secret restored locally; model only receives sanitized content |
| Multiple `edit` replacements with markers in `oldText` and `newText` | Correct regions match after permitted restoration; no unintended overwrite or unresolved marker reaches disk |
| Unknown marker, LRU-evicted entry, cleared vault, external destination | Existing policy enforced without fabricated restoration; no vault TTL is assumed |
| Invalid tool arguments | Prohibited or uninspectable operations fail safely without execution or plaintext diagnostics |
| Scanner/transform failure in result or request handlers | Proven safe replacement or supported cancellation; original sensitive content never reaches the provider despite dispatcher exception handling |
| Later handler reintroduces sensitive content | Captured final request remains sanitized under the supported configuration and effective handler order |
| Full-transcript transformation | Leading system message, tool declarations, roles, and call/result correlation remain valid |
| Resume, fork, reload, project transition | No stale registrations or unintended secret-state sharing |
| Parallel calls | Correlation remains correct; no secret crosses unrelated calls |
| MCP proxy, context-mode, subagents | Record actual interception and redaction at every claimed boundary |
| Notifications and guard logs | No plaintext fixture secrets; useful sanitized reason and correlation |
| OpenCode regression | Existing adapter's behavior and public entry point remain compatible |

Use failing regression tests before implementation for new behavior. Separate
adapter unit tests, fake-provider request tests, and real Pi integration tests.
Mock tests alone cannot establish Pi runtime or subprocess coverage.

## Verification gates and completion

Existing repository commands to run during implementation, matching
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

Add Pi-specific smoke and integration gates when the adapter exists. Apply the
coverage thresholds from `docs/QualityContract.md` (lines >= 90%, branches >= 85%)
without global regression and record actual coverage results, not only test
success. Missing required checks are BLOCKED unless an exception is approved.
Use scoped mutation testing only where justified; reserve full Stryker runs for
global-baseline work according to `AGENTS.md`.

Complete this migration only when the phase-1 feasibility gate passes, the tested
Pi artifact loads, prohibited
operations have no side effects, supported provider requests contain no fixture
secrets, permitted restoration works, lifecycle tests pass, OpenCode gates pass,
and the integration coverage matrix is backed by evidence for the documented
provider, extension versions, and handler order. Record versions, commands,
outcomes, exceptions, and uncovered paths; never infer untested results.

## Decisions and their deadlines

1. Before phase 2: validate the initial Pi 1.1.0/Windows/DeepSeek configuration, fixed extension versions, and effective handler order. Widen compatibility only with new acceptance evidence.
2. Before phase 2: prove final-request ordering and safe replacement or supported cancellation on scanner/transform failure; throwing from a caught handler is insufficient.
3. Before phase 2: prove in-place tool-argument restoration or select narrow supported wrappers.
4. In phase 1, define claimed coverage for `powershell`, `grep`, `find`, `ls`, user shell, session persistence, non-text input, nested tools, and child processes; validate it in the relevant implementation/integration phase.
5. Before implementing lifecycle handling in phase 2: define vault isolation and behavior after resume/fork/reload, using current LRU eviction and explicit clearing rather than an assumed TTL.
6. After local end-to-end acceptance: decide separate local artifact versus a published Pi package; no package rename assumed.

## References

- Official Pi agent extension documentation: https://pi.dev/docs/latest/extensions
- Pi extension API: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md
- Pi MCP integration: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/mcp.md
- Pi extension types: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/types.ts
- Pi extension dispatcher: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/runner.ts
- Pi MCP adapter: https://github.com/nicobailon/pi-mcp-adapter
- Repository guidance: `AGENTS.md`, `docs/QualityContract.md`, `README.md`, `SECURITY.md`, `scripts/quality-gate.sh`
- Reviewed installed contracts: `C:\Users\Antunes\AppData\Roaming\npm\node_modules\@earendil-works\pi-coding-agent\dist\core\extensions\runner.js`, `types.d.ts` in the same directory, and `dist\core\tools\edit.js` / `powershell.js` in that package.

Upstream links are discovery references. Check the matching release or installed
source before relying on an API contract.
