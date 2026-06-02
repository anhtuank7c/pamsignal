# V9 — Self-contained Tokens

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x18-V9-Self-contained-Tokens.md>

## Status for PAMSignal: ⚪ **N/A**

PAMSignal does not **mint** or **verify** self-contained tokens. It does not issue JWTs, PASETOs, or any other signed/encrypted token format. The webhook tokens it carries (Telegram bot tokens, Slack webhook URLs with embedded secrets, bearer headers) are **opaque credentials** stored as bytes — PAMSignal treats them as black-box strings that go from config → memfd → curl. The V9 controls (algorithm allow-list, audience binding, nbf/exp validation, key rotation policy, revocation list) have no target.

The handling of those opaque tokens **is** in scope, but the relevant requirements live in:

- **V14 Data Protection** — kept out of argv, env, and journal.
- **V13.2 Secret management** — file permissions on the config file.
- **V12.3 mTLS** — when paired with TLS client cert / key material.

## When this would become applicable

If PAMSignal ever issues or validates a self-contained token — for example a JWT it signs to attach to webhook requests — V9 would apply. Not currently planned.

If that ever changes:

1. Replace this N/A page with a full chapter audit guide.
2. Audit signing algorithm, claim validation, and key rotation against V9.1–V9.5.
3. Document the new flow in `docs/architecture.md`.

## How to mark this in an audit report

```markdown
| V9 Self-contained Tokens | N/A | Stores opaque webhook tokens; does not mint or verify JWT/PASETO (see V14 for opaque-token handling) |
```
