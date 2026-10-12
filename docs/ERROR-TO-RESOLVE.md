## Summary: OpenCode Security Guard and the Claude signature error

### 1. The problem

The [opencode-security-guard](https://github.com/marioalexandreantunes/opencode-security-guard) plugin causes an error when we use Claude Haiku 5.5 through the OpenCode Go Plan:

```
Upstream request failed: [invalid_request_error]
messages.3.content.0:
Invalid `signature` in `thinking` block
```

The error disappears when we disable the plugin. It happens even without real secrets in the history.

### 2. Cause (confirmed in the code)

The `experimental.chat.messages.transform` hook (`src/plugin.ts`) calls `redactSkipping` on every key of each `part`, except the structural ones (`PART_SKIP`: `id`, `type`, `time`, `tokens`, etc.). This includes the `metadata` of `reasoning` parts, where Claude stores the `signature`.

The `entropy-blob` rule (`src/rules.ts`) detects strings of 40 to 512 characters from `[A-Za-z0-9+=_-]` with uppercase, lowercase, digits and enough entropy. Claude signatures meet these criteria.

Isolated test performed:

```
thinking signature: <SECURITY_GUARD_REDACTED:entropy-blob:767ffffc3c4abbf0>
```

So the signature is rewritten even when there is no secret. The API validates the signature and rejects the request.

There is currently no "does this block contain a secret?" check before redaction.

### 3. Intended behavior

Security Guard must not block the agent, but protect the content transparently.

- Secrets are never exposed to the model.
- The agent keeps working normally.
- Messages are sanitized without causing signature errors.
- The mechanism works with different providers and models.
- Secrets remain recoverable locally through the vault.

### 4. Proposed solution (not yet implemented)

Distinguish modifiable content from signed content.

For normal messages: keep sanitization and replacing secrets with placeholders.

For signed `reasoning` blocks:

1. Do not redact the signature (`signature`, `redactedData`) at any depth. Any change invalidates it, even a false positive.
2. If the thinking text has no secrets, preserve the whole block.
3. If the thinking text has secrets, it cannot be redacted without invalidating the signature. Omit the block from the history.
4. Confirm the final history structure remains valid for the provider. Omitting a thinking block may require adjustments depending on API rules.

Planned changes (not implemented, documentation-only request):

- `src/redact.ts`: option to skip opaque keys.
- `src/plugin.ts`: `reasoning` handling in `messages.transform`.
- `tests/security-guard/chat-hooks.test.mts`: tests for preserved signatures and omitted blocks with secrets.

### 5. Expected result

Message / History → Security Guard → Detection and classification

- Normal content → secret redaction
- Signed thinking, no secrets → preserve signature
- Signed thinking, with secrets → omit block

→ Valid request to the provider → agent keeps executing

### 6. Acceptance criteria (current status)

- [ ] Claude Haiku 5.5 with thinking and no secrets: **fails today** (cause confirmed, fix not implemented).
- [ ] Claude Haiku 5.5 with secrets in normal message history: redaction exists; not validated against the real API.
- [ ] Claude Haiku 5.5 with secrets inside signed thinking blocks: omission not implemented yet.
- [ ] Several tools and consecutive cycles without signature errors: not validated.
- [ ] No secret exposure to the model: not validated end to end.
- [ ] Compatibility with other models using signatures: not validated.

### Conclusion

The solution is not to recalculate signatures or block the request. It is to leave signatures untouched and omit only the thinking blocks whose text contains secrets.

Important limit: if the provider requires a specific signed block to continue the conversation and does not allow its omission, there is no automatic continuity without rebuilding a valid session. In that case, a controlled recovery in a new session, with sanitized context, is preferable to sending secrets or invalid signatures.

Architecture principle: Sanitize what is mutable, preserve what is signed, reconstruct what cannot safely be preserved.
