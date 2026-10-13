# Mutation.md — Mutation testing

- **Date:** 2026-09-15 (full global run, all files)
- **Tool:** Stryker 10.0.0 (`command` runner, `coverageAnalysis: off`)
- **Command:** `npm run mutation` (`stryker run`, config in `stryker.conf.json`)
- **Scope:** `src/**/*.ts` minus `src/index.ts` (entry) and `src/rules.ts` (regex corpus)
- **Gate:** `break: 80`, `low: 80`, `high: 85` (target ≥ 85%); blocking weekly CI job
- **Baseline:** **87.05%** — 1 814 mutants, 123m9s

## What it measures

Stryker injects small faults (flip `>=`/`>`, invert an `if`, drop a `return`, change a string) and re-runs the suite. A mutant **survives** when the tests stay green: the suite does not pin that behaviour. Mutation score = killed / total. It measures *test effectiveness*, not code coverage.

`rules.ts` is excluded because its 53 regexes produce the bulk of the mutants (1 850 project-wide), most of them equivalent or unkillable without duplicating the regex in tests. Since 2026-09-13 (`scanner-property-tests`) the exclusion zone is covered by the **property/fuzz suite** instead: `npm run test:property` (fast-check, P-1…P-11 — per-rule true positives, pre-filter soundness, marker stability, benign corpus, decode budgets, security invariants; merge-blocking in CI + nightly large-count run; seed replay via `SG_FUZZ_SEED`). The property suite is deliberately not part of `npm test`, so Stryker's command runner and these scores are unaffected.

## Results

Homogeneous full run (`npm run mutation`; 1 814 mutants; 123m9s; 18 timeouts counted as detected, 0 errors, 0 uncovered). Score = (1 561 killed + 18 timeout) / 1 814 = **87.05%**.

| File | Score | Mutants | Killed | Survived | Reading |
| --- | ---: | ---: | ---: | ---: | --- |
| `bash.ts` | **95.3%** | 214 | 204 | 10 | strong |
| `blacklist.ts` | **86.1%** | 216 | 183 | 30 | strong |
| `config.ts` | **94.6%** | 168 | 159 | 9 | strong |
| `paths.ts` | **91.6%** | 119 | 109 | 10 | strong |
| `plugin.ts` | **81.0%** | 642 | 514 | 122 | at the floor — triage open |
| `project-dir.ts` | **89.6%** | 163 | 146 | 17 | strong |
| `redact.ts` | **79.3%** | 53 | 39 | 11 | below floor — hardening item |
| `tool-output.ts` | **97.1%** | 102 | 99 | 3 | strong |
| `vault.ts` | **97.0%** | 33 | 29 | 1 | strong |
| `write-policy.ts` | **78.9%** | 104 | 79 | 22 | below floor — hardening item |
| **Total** | **87.05%** | **1 814** | **1 561** | **235** | above the 80% floor |

(18 mutants timed out; they count as detected in the score but not in the `Killed` column.)

The per-file totals moved since the 2026-09-11 run (1 484 mutants): the `typed-log-boundary`, `bash-detection-gaps` and `make-test-suite-reproducible` changes landed in between and added/reshaped mutants, so rows are not directly comparable mutant-for-mutant — the table above is the new homogeneous baseline.

## Where the tests are weak

Two files sit below the 80% floor and are the next hardening items (see *Improvement plan* items 8–9): `redact.ts` (**79.3%**, 11 survivors) and `write-policy.ts` (**78.9%**, 22 survivors). `plugin.ts` (**81.0%**, 122 survivors) meets the floor but its survivors need triage against the approved taxonomy (item 10) — the count grew with the reshaped mutant set, not necessarily with new weak behaviour.

## Equivalent mutants

Not every survivor is a weak test. In regex/heuristic code (`paths.ts`, `bash.ts`) many mutants are **equivalent** — the pattern change does not affect any tested input, or is semantically identical; they are unkillable without an exhaustive corpus, so the raw score understates quality there. In the still-unhardened mid-tier files (`blacklist.ts`, `redact.ts`, `write-policy.ts`) survivors more often mark genuinely untested branches; `plugin.ts`, `config.ts`, `vault.ts`, `project-dir.ts` and `tool-output.ts` used to be in that camp and are now the counter-examples — after their hardening changes, all of their survivors are equivalents/defensive/cosmetic rather than untested logic.

Fresh-run accounting (2026-09-15 report `reports/mutation/mutation.json`, 235 survived). Confirmed carry-overs from the maintainer-approved taxonomy — no re-review needed:

- `tool-output.ts` (3): exactly the approved locations `43:9`, `43:31`, `50:36` (dense-array fallthrough ×2, null-skip guard).
- `vault.ts` (1): `29:13` (`if (true)` delete no-op).
- `bash.ts` (10): same count and classes as the approved 10 (gate lookaheads, `compose()` fallback, quantifier equivalents, quote-strip space, tokenizer split, short-token guards).

Open (require maintainer review before they can be called accepted — the contract forbids weakening by declaration):

- `plugin.ts` (122), `blacklist.ts` (30), `project-dir.ts` (17), `config.ts` (9), `paths.ts` (10), `redact.ts` (11), `write-policy.ts` (22): map each survivor to the approved classes in the change evidences below, or classify as new equivalents / new hardening tests. The 2026-09-11 scoped taxonomies remain the reference:
  - `plugin.ts`: `openspec/changes/archive/2026-09-10-strengthen-plugin-mutation-tests/evidence.md` (class A/B).
  - `bash.ts`: `openspec/changes/archive/2026-09-11-bash-per-category-cases/evidence.md`.
  - `config.ts`: `openspec/changes/archive/2026-09-11-strengthen-config-mutation-tests/evidence.md` (plus the four `logPath` guards at `src/config.ts:84` from `typed-log-boundary`).
  - `vault.ts`: `openspec/changes/archive/2026-09-11-strengthen-vault-mutation-tests/evidence.md`.
  - `project-dir.ts`: `openspec/changes/archive/2026-09-11-strengthen-project-dir-mutation-tests/evidence.md`.
  - `tool-output.ts`: `openspec/changes/archive/2026-09-11-strengthen-tool-output-mutation-tests/evidence.md`.
  - `paths.ts`: `openspec/changes/archive/2026-09-10-strengthen-paths-mutation-tests/evidence.md`.

## Improvement plan (highest return first)

1. ~~**`paths.ts` — table-driven `SENSITIVE_PATHS` test.** Positive/negative per pattern; kills dozens of string/regex mutants at once.~~ **Done** (2026-09-10): table-driven catalogue plus `EXTRA_PATHS`, empty-log, `escapeRe` and `diskHasSecrets` coverage; `paths.ts` rose from 29.9% to **96.0%**.
2. ~~**`plugin.ts` — hook branches.** Log events, rehydration flag combinations, and error paths of `before`/`after`.~~ **Done** (2026-09-10): scoped score **51.4% → 84.18%** (kills-only 83.05%); three new suites (`plugin-hook-branches`, `plugin-chat-dispose`, `plugin-mode-quiet`); see `openspec/changes/archive/2026-09-10-strengthen-plugin-mutation-tests/evidence.md`.
3. ~~**`bash.ts` — per-category cases.** Env, write-verbs and network patterns.~~ **Done** (2026-09-11): scoped score **61.2% → 95.22%**; new suite `bash-patterns.test.mts`; 10 accepted equivalents (harness-verified, human-reviewed); see `openspec/changes/archive/2026-09-11-bash-per-category-cases/evidence.md`.
4. ~~**`config.ts` — `writeLog` rotation and failure path**, plus `SECURITY_GUARD_EXTRA_PATHS`.~~ **Done** (2026-09-11): scoped score **62.3% → 94.81%**; four suites (`config-defaults`, `config-log-level`, `config-log-fallback`, `config-log-mkdir`) plus the `plugin-mode-quiet` `QUIET` fix; 4 accepted equivalents (verified against source, maintainer-approved); see `openspec/changes/archive/2026-09-11-strengthen-config-mutation-tests/evidence.md`.
5. ~~**`vault.ts` — LRU/limit edge cases.**~~ **Done** (2026-09-11): scoped score **63.6% → 96.97%**; new `vault-limit.test.mts` env matrix plus the extended `vault.test.mts` edge cases; 1 accepted equivalent (`if (true)` delete no-op), 7 eviction-loop timeouts counted as detected; see `openspec/changes/archive/2026-09-11-strengthen-vault-mutation-tests/evidence.md`.
6. ~~**`project-dir.ts` — template/flag literals and the bootstrap matrix.**~~ **Done** (2026-09-11): scoped score **57.5% → 92.45–94.34%** (two runs); the extended `project-dir.test.mts` (9 → 13 tests) pins the `EXAMPLE` content by exact equality, the byte-exact `.gitignore` prefix matrix, the `BootstrapResult` flags, the `referencesProjectDir` anchor/trim, the recursive `mkdirSync` and the fail-open serialisation; 8 accepted equivalents (maintainer-approved); see `openspec/changes/archive/2026-09-11-strengthen-project-dir-mutation-tests/evidence.md`.
7. ~~**`tool-output.ts` — `TOOL_SKIP` keys, depth/node/length boundaries and the fail-closed path.** 71.6% (73/102, 29 survived); **target ≥ 90%**. Survivors: the 7 `TOOL_SKIP` members, the `TOOL_MAX_DEPTH`/`TOOL_MAX_NODES`/`TOOL_MAX_STRING` bound comparisons, the `seen`/array guards, the `enumerable` flags and the `FAILED_PLACEHOLDER`/fail-closed branch.~~ **Done** (2026-09-11): scoped score **71.6% → 97.06%** (95 killed, 4 timeout, 3 survived; killed/timeout split is runner jitter); three new suites (`tool-output-skip`, `tool-output-budgets`, `tool-output-neutralise`); 3 accepted equivalents (dense-array fallthrough ×2, null-skip guard; harness-verified, maintainer-approved); see `openspec/changes/archive/2026-09-11-strengthen-tool-output-mutation-tests/evidence.md`.
8. **`write-policy.ts` — boundary hardening (new, 2026-09-15).** 78.9% (22 survived of 104): `resolveProjectRoot`/`canonicalizeRoot`/`classifyDestination`/`writeTargets` branches at 20/22/31–33/78/88/106/110–111. Target ≥ 85%.
9. **`redact.ts` — branch hardening (new, 2026-09-15).** 79.3% (11 survived of 53): string/option branches at 9/29/48/53–56/66. Target ≥ 85%.
10. **`plugin.ts` — survivor triage (new, 2026-09-15).** 81.0% (122 survived of 642): map each survivor to the class A/B taxonomy or file new hardening tests; no new equivalents without maintainer approval. Target ≥ 85%.

The 2026-09-15 global run measures the total at **87.05%** (1 579/1 814 incl. timeouts) — above the contract's 80% floor without the `rules.ts` corpus, and already inside the **85–87%** target band the 2026-09-11 plan projected. Items 8–10 are the remaining headroom toward a higher ratchet; `blacklist.ts` (30 survivors) follows once they land.

## Raising the gate

Ratchet history: `break` 50 (2026-09-09 approval) → 62 (post-hardening) → **80** (this change, 2026-09-15, on the fresh 87.05% baseline with ~7 points of margin). Bands realigned so the report is coherent: green ≥ 85 (contract target), yellow 80–85, fail < 80 (`high: 85`, `low: 80`, `break: 80`). The gate is blocking in the weekly CI job. `break` SHALL NOT be lowered to pass — a score below 80 stops the ratchet and is reported BLOCKED. Keep the 80% floor as the approved minimum.

## Post-review scoped hardening

These are focused re-runs after the baseline above, not a replacement global measurement:

| Scope | Result | Change |
| --- | ---: | --- |
| `src/redact.ts` | **88.68%** (47/53 incl. 3 timeout; 6 survived) | nested secret + cycle coverage and exact failure-event assertions |
| `src/write-policy.ts` | **84.62%** (88/104; 16 survived) | patch target grammar, whitespace, trailing-text and canonical-root assertions |
| `src/plugin.ts` | **81.46%** (523/642 incl. 6 timeout; 119 survived) | summary emission with counters-only and blocks-only sessions |

The global `87.05%` baseline remains the contractual measurement until a new full run is requested. Scoped survivors still include approved equivalent/defensive cases; they are not accepted as a reason to lower `break`.

## Reproduce

```sh
npm run mutation
# reports (gitignored): reports/mutation/mutation.html and mutation.json
```
