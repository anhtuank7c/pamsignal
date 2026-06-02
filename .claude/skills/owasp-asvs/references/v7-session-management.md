# V7 — Session Management

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md>

## Status for PAMSignal: ⚪ **N/A**

PAMSignal has no sessions. There is no session ID, no cookie, no idle timeout, no absolute timeout, no fingerprint binding, no suspicious-session signal — because there is no user authentication and no per-user state (see V6 N/A). The V7 controls (session ID entropy, rotation on privilege change, secure cookie attributes, logout invalidation) have no target.

The daemon is a single long-running process. Its lifecycle events (start, ready, SIGHUP reload, shutdown) are logged via journald (see V16) but are not "sessions" in the ASVS sense.

## When this would become applicable

If PAMSignal grows a per-client connection state — for example, a long-lived admin connection authenticated once at the start — V7 would apply. Not currently planned.

If that ever changes:

1. Replace this N/A page with a full chapter audit guide.
2. Audit session creation, rotation, and termination against V7.1–V7.5.
3. Document the new trust boundary in `docs/architecture.md`.

## How to mark this in an audit report

```markdown
| V7 Session Management | N/A | No sessions in PAMSignal |
```
