# V17 — WebRTC

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x26-V17-WebRTC.md>

## Status for PAMSignal: ⚪ **N/A**

PAMSignal has no realtime audio/video, no peer connections, no signalling channel, no STUN/TURN involvement. The V17 controls (peer connection security, signalling channel auth, ICE/STUN/TURN configuration, media path encryption, DTLS-SRTP) have no target.

## When this would become applicable

Realistically never — PAMSignal's purpose is one-shot text alerts. There is no foreseeable scenario in which it grows a WebRTC surface. Listed here for completeness so the chapter is explicitly marked N/A in every audit report rather than silently omitted.

## How to mark this in an audit report

```markdown
| V17 WebRTC | N/A | No realtime A/V surface; not on the roadmap |
```
