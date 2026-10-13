# QualityContract.md — Quality Contract

## OpenSpec
- Read this file before creating, editing, or executing `tasks.md`.
- During planning, update the change entry below with scenarios, tests, commands, and risks; reference it from tasks.
- For behavioral changes: define acceptance scenarios → write failing tests → implement → refactor → validate.
- Mark tasks complete only with appropriate evidence. Never invent results.
- Require full validation before sync/archive; rerun after relevant changes.

## Gates
- Test success, failure, boundaries, and permissions where relevant.
- Require deterministic, isolated tests; add integration tests at system boundaries.
- Coverage: lines ≥ $90\%$, branches ≥ $85\%$; no global regression.
- Business-logic mutation score ≥ $80\%$.
- Lint, formatting, and applicable type checks must pass.
- No High/Critical security findings.
- Missing tools or unsupported metrics mean BLOCKED, not PASS; exceptions require human approval.
- Never weaken tests, thresholds, or exclusions to pass.
- Require human review for security-sensitive changes and ignored mutants.

## Stack
Use actual project commands, not assumed scripts:
- Rust: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`; cargo-llvm-cov, cargo-mutants.
- Python: Ruff, configured type checker, pytest/coverage.py, mutmut.
- TS/JS: configured linter/formatter, TypeScript checks where applicable, Vitest/Jest, Stryker.
- AutoIt: Au3Check and executable assertion/integration tests on Windows; isolate GUI state.

## Execution
- `scripts/quality-gate.sh` orchestrates configured gates, including Windows execution where needed.
- CI enforces gates; local hooks are supplementary.
- Record commands, exit codes, validated revision/state, metrics, and report links.
- After three unsuccessful correction attempts, report BLOCKED.
- Serena maps impact; Qdrant supplies history, not authority.
- RTK must preserve failure status; retain full reports.

## Change Plans
Agent-editable; policy above requires human approval.

### quality-gates
- Scenarios/risks: coverage gate (lines ≥ 90%, branches ≥ 85%), formatter gate, scoped mutation gate. Risks: one-time format churn; mutation survivors.
- Tests/files: `tests/security-guard/unit-branches.test.mts`; `scripts/quality-gate.sh`; `stryker.conf.json`; `biome.json`; `.gitlab-ci.yml`.
- Commands/gates: `npm run typecheck`, `lint`, `format:check`, `test`, `coverage`, `build`, `smoke:dist` all pass; `npm run mutation` (nightly).
- Exceptions/approvals: the 80% floor is **met** — the 2026-09-11 global run measures **83.89%** (1 245/1 484). It was 55.54% scoped at the 2026-09-09 approval (`break: 50`, `high: 80`); the `break` ratchet has since been raised to **62** (`stryker.conf.json`). The recorded target is now **≥ 85%** (85–87% range), tracked as items 6–7 in `docs/MUTATION.md`. Rationale for not targeting >90%: ~84 accepted equivalents in `plugin.ts` (plus the smaller files' equivalents) cap the achievable score near ~93%, and the contract forbids fabricating tests to lift the number.
- Evidence/state: c8 coverage lines 99.13% / branches 94.62%; 269 tests pass; global Stryker **83.89%** — 1 245/1 484 detected, 239 survived, 15 timed out (2026-09-11, 32m20s; per-file table in `docs/MUTATION.md`); `scripts/quality-gate.sh` exit 0.
- Result: PASS (80% floor met; target ≥ 85%)

### strengthen-config-mutation-tests
- Scenarios/risks: pin `src/config.ts` log rotation (exact `LOG_MAX` boundary), the write-failure warn-once path, the `logAllows`/`LOG_LEVEL` matrix, the import-time defaults and fallbacks, and `QUIET`. Risks: none — tests-only change, no production code touched.
- Tests/files: new `tests/security-guard/config-defaults.test.mts`, `config-log-level.test.mts`, `config-log-fallback.test.mts`, `config-log-mkdir.test.mts`; edited `plugin-mode-quiet.test.mts`.
- Commands/gates: `npm test` (258 pass), `npm run typecheck`, `lint`, `format:check`, `coverage` (lines 99.07% / branches 94.43%), `build`, `smoke:dist` — all exit 0; scoped `npx stryker run --mutate src/config.ts` **94.81%** (73/77, 0 timeouts, 1m16s).
- Exceptions/approvals: 4 accepted equivalents (`norm` typeof guard, `norm` `"string"` literal, inner `MIN_LOG_RANK` `"info"` fallback, `appendFileSync` `"utf8"`) — verified against source, approved by the maintainer on 2026-09-11.
- Evidence/state: revision `5c0d8ce`; full record in `openspec/changes/archive/2026-09-11-strengthen-config-mutation-tests/evidence.md`; `docs/MUTATION.md` updated; `stryker.conf.json` untouched (global ratchet stays with the nightly run).
- Result: PASS

### strengthen-vault-mutation-tests
- Scenarios/risks: pin `src/vault.ts` `configuredMax()` env semantics (`SECURITY_GUARD_VAULT_MAX`: unset/invalid/non-positive/fractional/`Infinity`), re-store LRU refresh, repeated-store eviction, `max = 0`, negative-`max` guard, lookup miss, defensive `undefined` value. Risks: none — tests-only change, no production code touched.
- Tests/files: new `tests/security-guard/vault-limit.test.mts`; edited `tests/security-guard/vault.test.mts`.
- Commands/gates: `npm test` (269 pass), `npm run typecheck`, `lint`, `format:check`, `coverage` (lines 99.13% / branches 94.62%), `build`, `smoke:dist` — all exit 0; scoped `npx stryker run --mutate src/vault.ts` **96.97%** (25 killed, 7 timeouts, 1 survived, 1m04s).
- Exceptions/approvals: 1 accepted equivalent (`ConditionalExpression` `if (valueByHash.has(hash))` → `if (true)` at `src/vault.ts:29` — `delete` of an absent key is a no-op); 7 eviction-loop timeouts counted as detected. Verified against source (formal proof + differential fuzz, 0 divergences); approved by the maintainer on 2026-09-11.
- Evidence/state: uncommitted working tree on `main`; full record in `openspec/changes/archive/2026-09-11-strengthen-vault-mutation-tests/evidence.md`; `docs/MUTATION.md` updated; `quality-gates` main spec synced with the new requirement; `stryker.conf.json` untouched (global ratchet stays with the nightly run).
- Result: PASS
