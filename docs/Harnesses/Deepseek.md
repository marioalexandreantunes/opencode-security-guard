# DeepSeek Harness v2 plugin migration plan

## Status and objective

Planning only. No DeepSeek Harness adapter has been implemented or validated
by this document.

Adapt the existing OpenCode security guard to DeepSeek Harness (DSH), using
its Cordis plugin system. Reuse detection, redaction, path policy, blacklist,
and controlled secret-restoration logic while preserving OpenCode compatibility.
Keep `docs\Harnesses\Pi.md` and `docs\Harnesses\Codex.md` as separate host integration plans.

The requested target is **Harness v2**. Before implementation, identify the
exact DSH release or commit and compatible package versions. Do not assume
that the product's v2 designation means every package has a `2.x` version.
Documentation and upstream contracts rechecked on 2026-10-13. Discovery did not
find `dsh` on the current `PATH`; this does not rule out a source checkout or
another installation location. Installed-runtime compatibility remains unproven.
Start with one isolated profile, a selected provider, and a fixed plugin set
whose exact versions and middleware order are recorded and validated. Other
releases, profiles, providers, or plugin configurations require new evidence.

## Official documentation and ecosystem

Starting references provided by the user:

- Plugin ecosystem: https://github.com/topics/dsh-plugin
- First plugin tutorial: https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/

The topic page is useful for discovering community implementations. Use official
documentation and release-specific source as the authority for runtime contracts.
Do not infer security guarantees from a plugin's topic, popularity, or description.

### Documented plugin model; runtime validation pending

- A TypeScript module can export `name` and `apply(ctx)`.
- `Context` comes from `@deepseek-ai/cordis`.
- Declare consumed services through `inject`; Cordis waits for required services.
- `ctx` registrations are disposed when the plugin unloads.
- Use `ctx.effect()` to attach explicit resource cleanup.
- Configuration can use an exported `Config` type and a Schemastery schema.
- Configuration changes can hot-replace the plugin.
- A local patch can insert a plugin into `cordis.yml` composition.
- Installable bundles can declare `dsh.bundle.patch` pointing to a patch file.
- A browser client is optional and separate from host-side enforcement.

Start with host-side protection only. A settings card is not required to prove
the guard's behavior.

## Existing sources and proposed boundary

Use this repository's sources rather than copying or modifying the deployed
OpenCode bundle.

| Source | Intended reuse |
| --- | --- |
| `src/rules.ts` | Detection, fingerprints, encoded-secret handling, scan cache |
| `src/redact.ts`, `src/tool-output.ts` | Safe recursive redaction and failure behavior |
| `src/paths.ts`, `src/bash.ts` | Sensitive paths and shell-command policies |
| `src/write-policy.ts` | Canonical paths and project-boundary checks |
| `src/vault.ts` | Bounded in-memory restoration state |
| `src/blacklist.ts` | Literal blacklist and refresh semantics |
| `src/config.ts`, `src/project-dir.ts` | Configuration, sanitized logs, project state |
| `src/plugin.ts` | OpenCode orchestration to extract only where actually shared |

Add a dedicated Cordis entry point, provisionally `src/deepseek.ts`, with a
separate host artifact, provisionally `dist/deepseek-security-guard.js`.
Keep the OpenCode public export and build intact. Final package layout is an
implementation decision, not an instruction to rename the existing package.

Before starting, check whether an existing `dsh-security-guard` scaffold is
available and inspect its actual version, sources, and instructions. Treat a
scaffold or startup message as packaging evidence only, not active protection.
Choose one adapter home explicitly rather than implementing duplicate engines.

## Host integration mapping

| OpenCode behavior | DSH candidate | Required evidence |
| --- | --- | --- |
| Pre-execution blocking | `tools/pre-execute` and `ctx.tools.guard()` | Deny before dispatch using the actual frozen argument snapshot |
| Argument restoration | No pre-execute input rewriting in the reviewed upstream contract | Prove a narrow supported tool-owned integration or record a restoration blocker |
| Tool-result redaction | `tools/post-execute` | Replace results through the typed contract, not frozen objects |
| Final-result observation | `tools/result` | Observe only; final outcome is immutable |
| Full inference-boundary redaction | `llm/stream` waterfall | Sanitize content-bearing `GenerateOptions` fields before adapter invocation |
| Project state and cleanup | Cordis effects and verified agent/session lifecycle | Isolate vault, caches, counters, and blacklist scope |
| UI notices | Supported host notification/logging service | No OpenCode client dependency or plaintext secrets |

### Tool pipeline order

The reviewed tools documentation describes:

`tools/pre-execute` → monotonic guards → `tools/execute` →
`projectContent` → `tools/post-execute` → `finalizeContent` → `tools/result`.

Important consequences from the reviewed upstream contract, to recheck against
the selected release:

- Parsed arguments are snapshotted and deep-frozen before policy. `ToolExecutionInput.arguments` is readonly and `PreToolDecision` only allows `allow`, `deny`, `cancel`, or `ask`; input rewriting is explicitly excluded so history, audit, UI, and execution agree.
- The pre-execute waterfall is extensible and reorderable. A final synchronous
  guard provides monotonic denial: later listeners cannot turn denial into permission.
- Guards deny by returning a reason string. Confirm exceptions and failed policy
  listeners resolve safely in the targeted release.
- Post-execute policy can inspect or replace a result, but a tool-owned
  `finalizeContent` transform runs afterwards and can change model-facing content.
- Post-policy may replace `content` or the canonical `value`, not both. Replacing content preserves the original value available to programmatic/PTC callers; replacing value revalidates its output schema and regenerates content/metadata. Blocking removes the value.
- `tools/result` observes the frozen authoritative outcome; it is too late for
  ordinary result mutation.
- Canonical values, rendered content, UI cards, and agent-facing content may
  differ. Sanitizing one representation does not prove all are sanitized.

Use the final LLM boundary as an independently tested protection layer. Do not
assume post-execute redaction alone prevents later content reintroduction.

Do not plan restoration as mutation of the frozen pre-execute arguments. Before
phase 2, prove a supported tool-owned wrapper or equivalent public integration
that restores only for permitted local operations without leaking restored values
through history, UI, logs, or programmatic results. If none exists, full-parity
migration is BLOCKED; a reduced-scope prototype requires explicit acceptance.
The existing vault uses LRU eviction and explicit clearing, not a TTL.

### LLM boundary

The documented `llm/stream` waterfall receives full `GenerateOptions` and a
`next()` callback leading to the resolved adapter. Provider credentials remain
inside the adapter and are not part of this content-scanning contract.

Verify the release's request schema, listener ordering, retry paths, and alternate
generation APIs. Sanitize conversation and system content while preserving model
IDs, tool names, schemas, correlation IDs, non-text blocks, and protocol metadata.
Do not treat every request string as user content or redact authentication fields.

The reviewed `GenerateOptions` has `messages` and optional one-shot `system`
content. Loop-built requests carry system content in a leading system-role
message. Verify both forms, plus request-local tool/history projections, against
the selected release rather than assuming a separate system string always exists.

The waterfall's `next()` takes no replacement request argument. Prove the legal
request-transformation mechanism, including frozen nested messages and any
prepared-call state; do not assume `next(sanitizedOptions)` or private adapter
mutation is supported. Record middleware order and test a later listener that
reintroduces a fixture secret before adapter dispatch. Scanner failures must
short-circuit or reject through a validated path without delegating original
content, including lazy iterator consumption, retries, and fallback routes.

Identify any code that invokes adapters or tools directly instead of using
`ctx.llm` and `ctx.tools.execute()`. Such paths require separate coverage evidence.

## Migration phases

### 1. Establish version, baseline, and scope

- [ ] Read `AGENTS.md`, `docs/QualityContract.md`, existing tests, and build configuration.
- [ ] Run existing OpenCode gates and record the baseline.
- [ ] Identify exact Harness v2 release/commit and Cordis, tools, LLM, and schema package versions.
- [ ] Select the initial isolated profile, provider, fixed plugin set, effective middleware order, and required protection scope without recording credentials.
- [ ] Inspect any existing DSH scaffold before choosing the implementation location.
- [ ] Inventory tools, providers, profiles, agents, sessions, nested execution, and direct service calls.
- [ ] Include file read/write/edit/search/list tools, shell and PowerShell backends, native calls, and PTC `run_code` nested callers; inspect actual argument and canonical-output schemas.
- [ ] Establish a disposable `DSH_HOME` and dedicated test profile before loading the guard.
- [ ] Produce a coverage matrix for dispatch, model requests, UI, logs, persistence, and subagents.

Keep development experiments isolated from live Desktop/user profiles. Do not
modify unrelated profiles or assume a repository root from `process.cwd()`.

#### Mandatory feasibility gate before phase 2

- [ ] Prove pre-policy and monotonic denial prevent body dispatch in the selected release, including listener exceptions, invalid input, and cancellation before execution.
- [ ] Confirm argument immutability and the absence or presence of a supported rewrite API; prove the chosen restoration integration with actual write/edit execution and multi-edit matching semantics.
- [ ] Prove `content` replacement, schema-valid `value` replacement, and blocking independently; ensure every claimed programmatic/PTC confidentiality boundary protects the canonical value, not just rendered text.
- [ ] Prove legal transformation of full `GenerateOptions`, including leading system messages, one-shot `system`, and immutable nested request data, while preserving tool protocol and prepared-call invariants.
- [ ] Inject scanner/listener failures before delegation and during iterator consumption; prove original sensitive requests never reach the fake adapter or fallback/retry path and diagnostics stay sanitized.
- [ ] Reintroduce fixture secrets through result finalizers and later LLM middleware; prove the actual adapter/transport boundary remains protected under the fixed plugin configuration and order.
- [ ] Record versions, commands, outcomes, bypasses, and the chosen adapter home before shared-engine changes.

Proceed to phase 2 only when every required claim passes this gate. Missing safe
restoration, legal request transformation, or final-boundary ordering is BLOCKED
for full parity. Any reduced scope must be explicitly accepted and documented;
successful plugin loading or mock callbacks alone cannot satisfy this gate.

### 2. Implement the Cordis adapter and lifecycle

- [ ] Add the `name`/`apply` entry point and declare required `tools`/`llm` injection.
- [ ] Reuse existing scanner and policy modules without copying detection rules.
- [ ] Initialize project scope from verified execution/session context.
- [ ] Register listeners, guards, and explicit resource disposal through Cordis.
- [ ] Scope vault, cache, counters, logs, and blacklist by the intended project/session ownership.
- [ ] Test dependency loss, reload, duplicate loading, disposal, and pending asynchronous work.
- [ ] Verify whether dependency loss or reload leaves tools/model calls runnable without the guard; prevent or explicitly exclude any gap in claimed continuous enforcement.
- [ ] Preserve documented environment behavior; define configuration precedence if adding schema fields.

Use an exported schema for tunable DSH configuration, not an unvalidated object.
Restrict fields to existing requested guard behavior; no speculative UI or policies.

### 3. Implement pre-dispatch protection and restoration

- [ ] Map DSH tool names and arguments to existing path and shell checks.
- [ ] Apply shell checks to the actual shell/PowerShell backend and decide access restrictions for search/list tools; do not assume OpenCode tool-name checks cover DSH names.
- [ ] Use pre-execute policy for required asynchronous decisions; do not rewrite frozen arguments through the reviewed pre-execute contract.
- [ ] Use a monotonic guard for final synchronous denial checks where appropriate.
- [ ] Validate the frozen arguments that reach dispatch and prove caller/plugin mutation cannot change them after materialization.
- [ ] Enforce canonical destination boundaries, sensitive paths, symlinks, moves, deletes, and missing targets.
- [ ] Restore known markers only through the supported integration proven in phase 1, for permitted operations and destinations; preserve exact matching and multiple-edit semantics.
- [ ] Preserve existing unknown-marker, disabled-restoration, external-path, and inspection-failure behavior.
- [ ] Preserve sensitive-read mode semantics: block covered reads in `SECURITY_GUARD_MODE=block`; in `redact`, prove sanitized model-visible results and separately define canonical-value access.
- [ ] Test nested/programmatic tools and parallel calls through the full execution service.

If legal argument rewriting cannot be established, record a blocker or investigate
a narrow supported wrapper. Do not mutate private runtime state or silently
remove restoration.

### 4. Implement tool and inference redaction

- [ ] Replace sensitive results through the tested `tools/post-execute` return contract.
- [ ] Choose content replacement, schema-valid value replacement, or blocking per confidentiality claim; content-only replacement must not claim to hide canonical values from programmatic/PTC callers.
- [ ] Cover canonical values, text blocks, structured content, errors, and encoded secrets.
- [ ] Test `projectContent` and `finalizeContent` reintroduction after policy transforms.
- [ ] Intercept `llm/stream`, sanitize the intended content fields, and preserve streaming behavior.
- [ ] Use only the legal request-transformation mechanism proven in phase 1; handle leading system messages and one-shot `system` without changing route/configuration invariants.
- [ ] Cover user input, injected context, system instructions, resumed history, compaction, retries, and routing.
- [ ] Reproduce scanner/listener failure and confirm original sensitive content is never delegated.
- [ ] Exercise lazy stream iteration, failure before/after `next()`, retries, and cancellation; use fixed sanitized errors and never catch a scanner failure by delegating the original request.
- [ ] Verify final requests with a fake adapter; test actual serialization for supported providers.
- [ ] Record UI, session-storage, attachment, and log limitations independently of inference guarantees.

### 5. Verify ecosystem and profile interactions

- [ ] Test MCP calls routed through the DSH tools service and identify bypasses.
- [ ] Verify parent/subagent requests and project/vault ownership across agents.
- [ ] Test hot module/configuration replacement and cleanup of in-flight calls.
- [ ] Validate the initial isolated profile first; test Desktop/Web, CLI, or headless profiles individually before adding them to supported scope.
- [ ] Check other result/LLM middleware ordering and prove the final boundary stays protected.
- [ ] Verify blacklist refresh, halt semantics, sanitized notices, log rotation, and cache bounds.
- [ ] Document unsupported direct calls and channels instead of claiming universal interception.
- [ ] Repeat final-boundary and failure-injection tests with the fixed plugin set enabled; changes to versions, profiles, providers, or middleware order require renewed evidence.

### 6. Package, install, and document

- [ ] Build a dedicated host artifact without breaking the OpenCode bundle.
- [ ] Declare compatible host dependencies and verify current versions before adding packages.
- [ ] Add a bundle manifest with `dsh.bundle.patch` and a tested patch file.
- [ ] Test an absolute-path development overlay and packaged local installation in the isolated profile.
- [ ] Verify discovery, dependency injection, unload/reload, and plugin removal cleanup.
- [ ] Document exact supported releases, profiles, providers, configuration, installation, and protection scope.
- [ ] Publish only after every advertised protection has acceptance evidence.

## Acceptance scenarios

Use synthetic secrets assembled at runtime. Never paste real credentials or the
guard's concrete marker literal into commands or documentation. Use `<MARKER:…>`
notation and construct test markers from `MARKER`. Set temporary log and project
state paths before importing modules.

| Scenario | Observable success criterion |
| --- | --- |
| Clean input/result/request | Content and protocol remain unchanged |
| Sensitive read with `SECURITY_GUARD_MODE=block` | Covered read body is never invoked |
| Sensitive read with `SECURITY_GUARD_MODE=redact` | Read may execute; model-visible output and captured provider request contain no fixture secret; canonical-value access follows its separately stated policy |
| Sensitive write/edit or prohibited shell/PowerShell command | Tool dispatch is never invoked |
| Caller/plugin attempts argument mutation | Dispatched arguments remain the validated frozen snapshot; no unsupported rewrite is treated as restoration |
| Known marker in permitted write/edit | Original secret restored locally; model sees sanitized content |
| Multiple edits with markers in matching/replacement fields | Supported integration preserves exact matching and intended destinations; no unresolved marker or unintended secret overwrite reaches disk |
| Unknown marker, LRU-evicted entry, cleared vault, or external destination | Existing policy applied without fabricated restoration or an assumed TTL |
| Secret-bearing canonical/rendered/error result | Claimed model-visible representations contain no fixture secret |
| Programmatic/PTC caller receives a result | Canonical value is protected by schema-valid replacement or blocking where claimed; content-only redaction is not accepted as value protection |
| Finalizer reintroduces a secret | Captured final LLM request remains sanitized |
| Later LLM middleware reintroduces a secret | Actual adapter/transport request remains sanitized under the supported plugin set and effective order |
| Loop-built and one-shot system content | Both leading system messages and optional `system` are sanitized through a supported transformation without protocol damage |
| Prompt/system/history/compaction/retry | Captured adapter requests contain no fixture secret |
| Scanner/policy failure, lazy iterator failure, or retry | No original sensitive request delegated or sent through fallback; diagnostics remain sanitized |
| Cancellation | Not-yet-started prohibited work never starts; already-started work is drained and any side effects are recorded rather than claimed undone |
| Nested MCP/programmatic tool call | Full service pipeline interception proven, bypasses documented |
| Parallel calls/subagents/project switch | Correlation correct; no unintended secret-state sharing |
| HMR/disposal/dependency loss | No stale listeners, duplicate registrations, or abandoned vault state; any enforcement gap is prevented or explicitly outside the claimed scope |
| UI/logs/persistence | Each stated channel guarantee verified separately |
| OpenCode regression | Existing adapter and public entry point remain compatible |

Use failing tests before implementing new behavior. Separate module tests,
Cordis lifecycle tests, tools-service pipeline tests, fake-adapter request tests,
and end-to-end profile tests. Mocking event callbacks alone does not prove the
host pipeline or final provider request is protected.

## Verification gates and completion

Existing implementation gates, matching `scripts/quality-gate.sh`:

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

Add DSH-specific artifact, lifecycle, tools, LLM, and isolated-profile gates when
their implementation exists. Apply the coverage requirements in
`docs/QualityContract.md` (lines >= 90%, branches >= 85%) without global regression
and record actual coverage results. Missing required checks are BLOCKED unless
an exception is approved. Follow `AGENTS.md` for scoped mutation testing and
temporary artifact cleanup.

Complete the migration only after the phase-1 feasibility gate, with a tested
host bundle, denied operations with no prohibited side effects, supported requests
free of fixture secrets, permitted restoration, lifecycle isolation, passing
OpenCode gates, and a
versioned coverage matrix backed by recorded evidence for the selected release,
profile, provider, plugin set, middleware order, and accepted protection scope.
Installation or plugin startup alone does not establish security equivalence.
Report any accepted reduced-scope prototype separately; it is not a full migration
when restoration or required final-boundary protection remains unavailable.

## Decisions and their deadlines

1. Before phase 2: identify the Harness v2 release/commit and package versions; choose one adapter home after inspecting any available scaffold.
2. Before phase 2: fix the initial isolated profile, provider, plugin set, middleware order, and full-parity or explicitly accepted reduced scope.
3. Before phase 2: prove supported restoration despite frozen tool arguments, or mark the full-parity migration BLOCKED; no private mutation or implicit loss of restoration.
4. Before phase 2: prove legal request transformation and fail-safe delegation at the actual adapter/transport boundary, including later middleware and lazy stream failures.
5. In phase 1: distinguish rendered-content, canonical-value, PTC, direct-call, UI, persistence, subagent, and dependency-loss coverage; validate each claim in its relevant phase.
6. Before lifecycle implementation: define project/session vault ownership, LRU eviction, clearing, and in-flight-call handling across HMR and dependency loss.
7. After initial end-to-end acceptance: decide package layout and support expansion to other profiles/providers; require separate evidence for each.

## References

- User-provided plugin ecosystem: https://github.com/topics/dsh-plugin
- Official first-plugin tutorial: https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/
- Official tool tutorial: https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/tool
- Official configuration tutorial: https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/config
- Official repository: https://github.com/deepseek-ai/deepseek-harness
- Tool pipeline reference: https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.md
- Tools package contract: https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/core/tools/README.md
- Tool execution and decision types: https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/core/tools/src/index.ts
- LLM streaming contract: https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/llm/llm/src/index.ts
- LLM request types: https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/llm/llm/src/types.ts
- Cordis middleware semantics: https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cordis-primer.md
- Package/install guide: https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md
- Repository guidance: `AGENTS.md`, `docs/QualityContract.md`, `README.md`, `SECURITY.md`, `scripts/quality-gate.sh`
- Related integration plans: `docs\Harnesses\Pi.md`, `docs\Harnesses\Codex.md`

Upstream links are discovery references. Check the matching Harness v2 release
or installed source and record exact versions before relying on an API contract.

---

**AI disclosure:** This document was produced by artificial intelligence.
