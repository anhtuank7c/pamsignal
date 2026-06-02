# V8 — Authorization

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md>

## Status for PAMSignal: ⚪ **N/A (mostly)**

PAMSignal has **no per-resource authorization model**. There is no RBAC, no function-level access control, no tenant boundary, no IDOR surface — because there are no users (V6 N/A) and no inbound requests (V4 N/A). The V8 controls (function-level checks, per-resource scoping, multi-tenant isolation, OAuth scope enforcement) have no target.

The one authorization decision PAMSignal *does* make — "can this process read the system journal?" — is delegated to the operating system via standard Unix permissions. The `pamsignal` user is added to `systemd-journal` group (or equivalent), and the daemon is granted journal read access through that membership. This is covered under **V15.3 Process / privilege architecture**, not V8.

## When this would become applicable

If PAMSignal grows multi-tenant operation, per-user alert routing, or an admin control plane with multiple privilege levels, V8 would apply to those decisions. Not currently planned.

If that ever changes:

1. Replace this N/A page with a full chapter audit guide.
2. Audit function-level enforcement on every privileged operation.
3. Document the new trust boundary in `docs/architecture.md`.

## How to mark this in an audit report

```markdown
| V8 Authorization | N/A | Single trust boundary (unprivileged pamsignal user vs root); journal read access delegated to OS group membership; see V15.3 |
```
