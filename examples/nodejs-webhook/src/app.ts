import { timingSafeEqual } from 'node:crypto';

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import morgan from 'morgan';

const app = express();

// Express best practices: security headers and request logging
// Disable morgan during tests to avoid cluttering test output
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}
app.use(helmet());

// Parse JSON bodies (PAMSignal sends JSON payloads). 64 KB cap keeps an
// unauthenticated attacker from forcing unbounded JSON allocation; PAMSignal
// payloads are well under 4 KB in practice.
app.use(express.json({ limit: '64kb' }));

/**
 * Constant-time string comparison. `a === b` short-circuits at the first
 * differing byte, leaking the secret byte-by-byte via response-time
 * differences. timingSafeEqual requires equal-length buffers.
 */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    // Still do a fixed-length compare so total time stays input-independent.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/**
 * Strip control characters from user-controlled values before logging.
 * PAMSignal payloads are JSON, so an attacker can put newlines, ANSI escape
 * sequences, or fake log lines in any string field. Replace anything below
 * 0x20 (and DEL) with '?' and cap length so a malicious peer cannot inject
 * log entries or terminal escapes into the receiver's stdout.
 */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\x00-\x1f\x7f]/g;
export function safe(value: unknown): string {
  if (value === undefined || value === null) return String(value);
  return String(value).replace(CONTROL_CHARS, '?').slice(0, 200);
}

/**
 * Authentication Middleware
 *
 * Enforces the use of a Bearer token in the Authorization header.
 * Configure pamsignal.conf with:
 *   webhook_auth_header = Authorization: Bearer <token>
 */
const authenticate = (req: Request, res: Response, next: NextFunction): void => {
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    if (process.env.NODE_ENV !== 'test') {
      console.warn('[WARN] WEBHOOK_SECRET is not set. Accepting all requests.');
    }
    return next();
  }

  const authHeader = req.headers.authorization ?? '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice('Bearer '.length) : '';
  if (safeEqual(token, WEBHOOK_SECRET)) {
    return next();
  }

  if (process.env.NODE_ENV !== 'test') {
    console.warn(`[AUTH FAILED] Unauthorized access attempt from IP: ${req.ip}`);
  }
  res.status(401).json({ error: 'Unauthorized: Invalid or missing token' });
};

/**
 * PAMSignal Webhook Endpoint
 */
app.post('/webhook/pamsignal', authenticate, (req: Request, res: Response): void => {
  // express.json() silently skips parsing for non-application/json bodies
  // (req.body stays undefined). Without this explicit 415 a text/plain POST
  // would fall through to the payload validator and return 400, which is
  // technically wrong: ASVS-aligned APIs answer 415 for unsupported media
  // types so clients can tell the difference between "your body was bad"
  // and "I don't accept this content type".
  if (!req.is('application/json')) {
    res.status(415).json({ error: 'Unsupported Media Type: expected application/json' });
    return;
  }

  const payload = req.body;

  // Basic validation to ensure it's a valid PAMSignal ECS payload
  if (!payload || !payload.event || !payload.pamsignal) {
    if (process.env.NODE_ENV !== 'test') console.warn('[BAD REQUEST] Invalid payload format received');
    res.status(400).json({ error: 'Bad Request: Invalid payload format' });
    return;
  }

  const { event, user, source, host, process: proc, pamsignal } = payload;
  const eventAction = event.action;

  // Handle the different PAMSignal events
  if (process.env.NODE_ENV !== 'test') {
    switch (eventAction) {
      case 'login_success':
        console.log(`✅ [LOGIN_SUCCESS] User '${safe(user?.name)}' logged in via ${safe(source?.ip)} on ${safe(host?.hostname)} (PID: ${safe(proc?.pid)})`);
        break;

      case 'login_failure':
        console.log(`❌ [LOGIN_FAILED] Failed login attempt for user '${safe(user?.name)}' from ${safe(source?.ip)} on ${safe(host?.hostname)}`);
        break;

      case 'brute_force_detected':
        console.log(`🚨 [BRUTE_FORCE] ${safe(pamsignal?.attempts)} failed attempts detected from IP ${safe(source?.ip)} in ${safe(pamsignal?.window_sec)}s!`);
        break;

      case 'session_opened':
        console.log(`ℹ️ [SESSION_OPEN] Session opened for user '${safe(user?.name)}' on ${safe(host?.hostname)}`);
        break;

      case 'session_closed':
        console.log(`ℹ️ [SESSION_CLOSE] Session closed for user '${safe(user?.name)}' on ${safe(host?.hostname)}`);
        break;

      default:
        console.log(`[UNKNOWN_EVENT] Received unknown event action: ${safe(eventAction)}`);
        break;
    }
  }

  // Respond quickly to avoid tying up the sender
  res.status(200).json({ status: 'success', message: 'Event received' });
});

export default app;
