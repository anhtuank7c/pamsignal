# V6 — Authentication

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md>

## Status for PAMSignal: ⚪ **N/A**

PAMSignal does **not authenticate users**. It is a passive observer of PAM events — the operating system performs the actual authentication; PAMSignal merely reads the journal entries that result. There are no PAMSignal accounts, no passwords, no TOTP, no WebAuthn, no recovery flows, no rate-limited login endpoints. The V6 controls (password policy, MFA enrolment, breached-password check, account lockout, OOB tokens) have no target.

The daemon's own privilege model is covered under **V15 Secure Coding & Architecture** (runs as the unprivileged `pamsignal` user; no setuid bits).

The outbound webhook tokens / bearer headers are **not** authentication credentials *for* PAMSignal — they are credentials presented *by* PAMSignal to the alert destination. Those are covered under **V14 Data Protection** (kept out of argv) and **V12 Secure Communication** (sent over TLS).

## When this would become applicable

If PAMSignal grows a local control surface — for example, a Unix-domain admin socket that authenticates connecting peers — V6 would apply to that surface. Not currently planned.

If that ever changes:

1. Replace this N/A page with a full chapter audit guide.
2. Audit the new authentication flow against V6.1–V6.8.
3. Document the new trust boundary in `docs/architecture.md`.

## How to mark this in an audit report

```markdown
| V6 Authentication | N/A | PAMSignal observes PAM events; it does not authenticate users (see V15 for privilege drop) |
```
