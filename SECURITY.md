# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Pre-1.0 releases are supported on a best-effort basis; fixes land in the latest `0.1.x`.

## Reporting a vulnerability

Do not open a public issue for a security problem.

Report privately through GitHub:

1. in the repository, open **Issues** → **New issue** → **Report a vulnerability** (private reporting — enable it first in *Settings → Security*), or
2. contact the maintainer through their GitHub profile.

Please include:

- affected version or commit, and platform (macOS / Linux / Windows);
- a minimal reproduction (input, command, or hook payload) and the observed vs expected result;
- whether it is a false negative (a secret that should be redacted or blocked but is not) or a false positive;
- any workaround you already know.

## What counts as a vulnerability

In scope:

- a secret reaching the model, the log, or disk despite the guard (redaction bypass);
- a sensitive file read or written through a tool despite the guard;
- an exfiltration path (a marker or secret sent to the network) that is not blocked;
- a marker write-back that corrupts a file or writes an unresolved placeholder;
- a denial of service caused by the guard (unbounded memory or traversal, crash on untrusted input).

Configuration note: the guard does not execute arbitrary regular expressions from configuration. `re:` blacklist lines are ignored with a generic diagnostic, and `SECURITY_GUARD_EXTRA_PATHS` values are escaped literal terms. Existing configurations that rely on regex syntax must migrate to literal terms.

Out of scope (documented limitations, see [README.md](README.md#known-limitations)):

- secrets below the detection thresholds (short, low-entropy, unknown formats);
- binary input, Unicode obfuscation and nested or multiple encoding layers beyond the documented scanner limits;
- PII and other non-secret data;
- prompt injection and model behaviour;
- `rm`/`del` of a sensitive file (integrity, not exfiltration);
- shell constructs that evade the heuristic command parser;
- vulnerabilities in `opencode` or in the `@opencode-ai/plugin` SDK — report those upstream.

The full threat model and the known limitations live in [README.md](README.md#threat-model).

## Response

This is a small, maintainer-run project with no paid support and no SLA. Expect, best effort:

- acknowledgement within a few days;
- an assessment and, where possible, a fix or mitigation in the latest `0.1.x`;
- credit in the changelog or release notes, unless you ask to stay anonymous.

## Disclosure

Please allow a reasonable window to ship a fix before public disclosure. We will try to agree on a disclosure date with you.

## Safe harbour

Good-faith research that follows this policy will not be pursued or reported. Do not access, modify, or exfiltrate data that is not yours, and stop testing once you have proof of the issue.
