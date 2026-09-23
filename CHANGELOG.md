# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Scanner limits are documented, including text-only input, encoding limits, no recursive decoding, and UTF-8 and size limits for on-disk scans.
- Write, edit and patch destinations now resolve symlinks, junctions and linked parent directories before rehydration. Uninspectable destinations fail closed.
- **Breaking:** each live project instance now owns its log destination. If multiple projects use the same explicit `SECURITY_GUARD_LOG`, later projects receive isolated sibling files.
- Marker identities are opaque per process and cannot be linked across runs.
- Diagnostics and log records no longer expose configuration content, raw shell commands, engine messages or personal paths where possible.
- **Breaking:** Configurable blacklist and extra sensitive path settings are literal-only; `re:` lines are ignored and arbitrary regex execution is removed.
- Log records use stable payloads and lowercase log levels.

### Fixed

- **Breaking:** Full writes with rehydration disabled now fail closed for existing targets that contain secrets or cannot be inspected, including oversized, non-regular, dangling-link and filesystem-error cases.
- `blocked.write.fullrewrite` now records stable inspection reasons; the diagnostic log schema is revision 12.
- Invalid write arguments, including cyclic values, `BigInt` values and throwing accessors, now return a coded diagnostic instead of throwing.

## [0.1.0] - 2026-09-09

### Added

- Secret redaction at the inference boundary: user prompts (`chat.message`), full history (`experimental.chat.messages.transform`), system prompt (`experimental.chat.system.transform`) and tool output (`tool.execute.after`).
- Detection engine (regex rules + Shannon entropy) with a cheap pre-filter, curated provider-token rules, and encoded-secret decoding (base64, hex, percent) capped per scan.
- Vault-based secret rehydration for `write`/`edit`/`patch` (default) and opt-in for `bash`, with a worktree destination policy and marker write-back protection.
- Command guard (`tool.execute.before`): blocks sensitive-file access, environment/variable dumps, plaintext secrets, network exfiltration and marker write-back.
- Cross-platform support with Windows cmd `copy`/`move`/`ren` detection and OS-independent path normalization.
- Data-driven bash environment-pattern corpus (POSIX, PowerShell, cmd, interpreters, eval bypass).
- One-step install scripts for macOS and Windows.
- Configurable log level (`SECURITY_GUARD_LOG_LEVEL`), log rotation and runtime safeguards.

### Changed

- Split the plugin into focused TypeScript modules with a single public export, `SecurityGuard`.
- Memoized clean history scans with a bounded, negative-only LRU cache.
- Hardened redaction coverage of the chat, messages and system surfaces.

### Fixed

- Closed audit findings covering inference-boundary coverage, recursive tool-output redaction with fail-closed budgets and rehydration destination policy.

### Security

- Fail-closed redaction: a scanner failure suppresses the output instead of leaking it.
- Sensitive-path block list (`.env`, `.ssh/`, `*.pem` and cloud credentials) enforced for reads, writes and shell commands.
- Anti-exfiltration: plaintext secrets in commands, environment dumps, and network commands carrying a marker are blocked.

[Unreleased]: https://github.com/marioalexandreantunes/opencode-security-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/marioalexandreantunes/opencode-security-guard/releases/tag/v0.1.0
