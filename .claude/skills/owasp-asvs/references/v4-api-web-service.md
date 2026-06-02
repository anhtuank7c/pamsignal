# V4 — API & Web Service

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md>

## Status for PAMSignal: ⚪ **N/A**

PAMSignal has **no inbound API**. It is a one-way daemon: it consumes events from the local systemd journal and *makes* outbound HTTPS calls via fork+exec curl. It never opens a listening socket, never accepts JSON-RPC, REST, GraphQL, gRPC, or WebSocket connections. The V4 controls (request schema enforcement, error-response shape, GraphQL depth limits, gRPC interceptors, WebSocket origin validation) have no target.

The outbound curl invocation **is** in scope, but the relevant requirements live in:

- **V12 Secure Communication** — TLS configuration on the outbound call.
- **V14 Data Protection** — secrets in argv / env / memfd.
- **V15 Secure Coding** — fork+exec isolation.

## When this would become applicable

If PAMSignal grows an inbound surface — e.g., a health-check endpoint, a remote-control socket, or a webhook receiver — this chapter would apply. Not currently planned.

If that ever changes:

1. Replace this N/A page with a full chapter audit guide.
2. Audit schema validation, rate limiting, and error-response shape.
3. Document the new trust boundary in `docs/architecture.md`.

## How to mark this in an audit report

```markdown
| V4 API & Web Service | N/A | No inbound API; outgoing HTTPS only (see V12, V14, V15) |
```
