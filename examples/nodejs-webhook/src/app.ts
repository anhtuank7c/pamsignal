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

// Parse JSON bodies (PAMSignal sends JSON payloads)
app.use(express.json());

/**
 * Authentication Middleware
 * 
 * Enforces the use of a Bearer token in the Authorization header.
 * Note: To connect this directly to PAMSignal, you will need a reverse proxy 
 * (like Nginx) to inject the `Authorization: Bearer <token>` header, as 
 * PAMSignal does not natively send custom headers for webhooks yet.
 */
const authenticate = (req: Request, res: Response, next: NextFunction): void => {
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    if (process.env.NODE_ENV !== 'test') {
      console.warn('[WARN] WEBHOOK_SECRET is not set. Accepting all requests.');
    }
    return next();
  }

  const authHeader = req.headers.authorization;

  // 1. Check Bearer Token
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (token === WEBHOOK_SECRET) {
      return next();
    }
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
        console.log(`✅ [LOGIN_SUCCESS] User '${user?.name}' logged in via ${source?.ip} on ${host?.hostname} (PID: ${proc?.pid})`);
        break;

      case 'login_failure':
        console.log(`❌ [LOGIN_FAILED] Failed login attempt for user '${user?.name}' from ${source?.ip} on ${host?.hostname}`);
        break;

      case 'brute_force_detected':
        console.log(`🚨 [BRUTE_FORCE] ${pamsignal?.attempts} failed attempts detected from IP ${source?.ip} in ${pamsignal?.window_sec}s!`);
        break;

      case 'session_opened':
        console.log(`ℹ️ [SESSION_OPEN] Session opened for user '${user?.name}' on ${host?.hostname}`);
        break;

      case 'session_closed':
        console.log(`ℹ️ [SESSION_CLOSE] Session closed for user '${user?.name}' on ${host?.hostname}`);
        break;

      default:
        console.log(`[UNKNOWN_EVENT] Received unknown event action: ${eventAction}`);
        break;
    }
  }

  // Respond quickly to avoid tying up the sender
  res.status(200).json({ status: 'success', message: 'Event received' });
});

export default app;
