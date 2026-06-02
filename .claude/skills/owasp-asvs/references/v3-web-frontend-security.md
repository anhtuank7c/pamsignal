# V3 — Web Frontend Security

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md>

## Status for PAMSignal: ⚪ **N/A**

PAMSignal is a C daemon with **no browser-rendered surface**. It has no HTTP server, no HTML output, no JavaScript, no DOM, no template engine, and no client-side code of any kind. None of the V3 controls (CSP, Trusted Types, DOM XSS defence, browser hardening headers, CORS, postMessage validation, X-Content-Type-Options) have a meaningful target in this codebase.

## When this would become applicable

This chapter becomes in-scope only if PAMSignal grows a web UI — for example a status page, a config editor, or a webhook receiver with a browser-served admin panel. None of these are on the roadmap; the project's positioning (`MEMORY.md` → PAMSignal positioning: layer-3 detection-alerting only) explicitly rules them out.

If that ever changes:

1. Replace this N/A page with a full chapter audit guide.
2. Add a corresponding pre-merge check to `/review-code`.
3. Document the new trust boundary in `docs/architecture.md`.

## How to mark this in an audit report

```markdown
| V3 Web Frontend Security | N/A | No browser-rendered surface in PAMSignal |
```
