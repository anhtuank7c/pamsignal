# V10 — OAuth & OIDC

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md>

## Status for PAMSignal: ⚪ **N/A**

PAMSignal performs no OAuth or OIDC flows. It is not an authorization server, not a resource server, and not a client. The V10 controls (authorization code flow, PKCE, state parameter, client registration, token endpoint, audience binding, dynamic client registration) have no target.

The webhook tokens it carries are **not** OAuth tokens — Slack incoming-webhook URLs and Telegram bot tokens are static credentials issued by the destination platform out-of-band. They are handled as opaque secrets (see V14).

## When this would become applicable

If PAMSignal grows OAuth flows — for example, to authenticate to a destination that requires OIDC, or to enforce OAuth on a future admin surface — V10 would apply.

If that ever changes:

1. Replace this N/A page with a full chapter audit guide.
2. Audit the chosen flow against V10.1–V10.6 (authorization code + PKCE, state binding, token validation).
3. Document the new flow in `docs/architecture.md`.

## How to mark this in an audit report

```markdown
| V10 OAuth & OIDC | N/A | No OAuth/OIDC flows; webhook tokens are static opaque secrets (see V14) |
```
