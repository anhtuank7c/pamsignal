/**
 * Unit tests for the PAMSignal Express webhook receiver.
 *
 * Uses supertest against the Express `app` directly so no transport is
 * involved — these tests pin down the in-process behavior of the request
 * handler, the security defenses (timing-safe Bearer compare, body size cap,
 * Content-Type validation, log injection sanitization), and the per-action
 * dispatch logic.
 *
 * Real-transport tests live in integration.test.ts and mtls.test.ts.
 */

import request from 'supertest';
import app, { safe, safeEqual } from '../src/app';

const SECRET = 'test-secret';

const VALID_PAYLOAD = {
  event: { action: 'brute_force_detected' },
  source: { ip: '203.0.113.50' },
  pamsignal: { attempts: 12, window_sec: 300 },
};

const auth = () => ({ Authorization: `Bearer ${SECRET}` });

beforeAll(() => {
  process.env.WEBHOOK_SECRET = SECRET;
  // Default Jest environment NODE_ENV=test already silences the dispatch
  // print() block. Suppress the warn-path noise too.
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterAll(() => {
  jest.restoreAllMocks();
  delete process.env.WEBHOOK_SECRET;
});

// =============================================================================
// Authentication
// =============================================================================

describe('Authentication', () => {
  it('rejects requests without a token', async () => {
    const response = await request(app).post('/webhook/pamsignal').send(VALID_PAYLOAD);
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: 'Unauthorized: Invalid or missing token' });
  });

  it('rejects an invalid Bearer token', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', 'Bearer wrong-token')
      .send(VALID_PAYLOAD);
    expect(response.status).toBe(401);
  });

  it('rejects an empty Bearer token', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', 'Bearer ')
      .send(VALID_PAYLOAD);
    expect(response.status).toBe(401);
  });

  it('rejects an Authorization header without the Bearer prefix', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', SECRET)
      .send(VALID_PAYLOAD);
    expect(response.status).toBe(401);
  });

  it('rejects an Authorization header with the wrong scheme', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Basic ${SECRET}`)
      .send(VALID_PAYLOAD);
    expect(response.status).toBe(401);
  });

  it('rejects a Bearer token that is a prefix of the real secret', async () => {
    // Covers the timing-safe compare's unequal-length branch.
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET.slice(0, 5)}`)
      .send(VALID_PAYLOAD);
    expect(response.status).toBe(401);
  });

  it('accepts a valid Bearer token', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .send(VALID_PAYLOAD);
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('success');
  });

  it('allows requests when WEBHOOK_SECRET is unset', async () => {
    delete process.env.WEBHOOK_SECRET;
    try {
      const response = await request(app).post('/webhook/pamsignal').send(VALID_PAYLOAD);
      expect(response.status).toBe(200);
    } finally {
      process.env.WEBHOOK_SECRET = SECRET;
    }
  });
});

// =============================================================================
// Content-Type validation
// =============================================================================

describe('Content-Type', () => {
  it('rejects text/plain with 415', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .set('Content-Type', 'text/plain')
      .send('not json');
    expect(response.status).toBe(415);
    expect(response.body.error).toMatch(/Unsupported Media Type/);
  });

  it('rejects application/x-www-form-urlencoded with 415', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send('x=1');
    expect(response.status).toBe(415);
  });

  it('accepts application/json', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .send(VALID_PAYLOAD);
    expect(response.status).toBe(200);
  });

  it('runs auth before media-type validation (unauthed wrong-CT → 401, not 415)', async () => {
    // Don't tell an unauthenticated peer anything about the endpoint
    // beyond "you need auth". Wrong CT without auth must still 401.
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Content-Type', 'text/plain')
      .send('not json');
    expect(response.status).toBe(401);
  });
});

// =============================================================================
// Body size limit (DoS defense)
// =============================================================================

describe('Body size limit', () => {
  it('rejects bodies over 64 KB with 413', async () => {
    const big = 'A'.repeat(65 * 1024);
    const payload = JSON.stringify({ event: { action: 'x' }, pamsignal: {}, pad: big });
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .set('Content-Type', 'application/json')
      .send(payload);
    expect(response.status).toBe(413);
  });

  it('accepts bodies well under the limit', async () => {
    const small = 'A'.repeat(10 * 1024);
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .send({ event: { action: 'x' }, pamsignal: {}, pad: small });
    expect(response.status).toBe(200);
  });
});

// =============================================================================
// Payload shape validation
// =============================================================================

describe('Payload validation', () => {
  it('rejects an empty object', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .send({});
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: 'Bad Request: Invalid payload format' });
  });

  it('rejects a payload missing the event object', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .send({ pamsignal: { attempts: 1 } });
    expect(response.status).toBe(400);
  });

  it('rejects a payload missing the pamsignal object', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .send({ event: { action: 'login_success' } });
    expect(response.status).toBe(400);
  });

  it('rejects an array at the top level', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .send([1, 2, 3]);
    expect(response.status).toBe(400);
  });

  it('rejects a literal JSON null', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set('Authorization', `Bearer ${SECRET}`)
      .set('Content-Type', 'application/json')
      .send('null');
    expect(response.status).toBe(400);
  });
});

// =============================================================================
// Event dispatch (verifies the per-action console.log output)
// =============================================================================

describe('Event dispatch', () => {
  let logSpy: jest.SpyInstance;
  let originalNodeEnv: string | undefined;

  beforeEach(() => {
    // Undo the Jest default NODE_ENV=test so the dispatch console.log block
    // runs. The console.warn spy installed in beforeAll keeps that channel
    // silent regardless.
    originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    if (originalNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  const lines = () => logSpy.mock.calls.map((c) => String(c[0]));

  it('logs login_success with user, ip, host, pid', async () => {
    const response = await request(app)
      .post('/webhook/pamsignal')
      .set(auth())
      .send({
        event: { action: 'login_success' },
        user: { name: 'alice' },
        source: { ip: '10.0.0.1' },
        host: { hostname: 'srv01' },
        process: { pid: 1234 },
        pamsignal: {},
      });
    expect(response.status).toBe(200);
    const all = lines().join('\n');
    expect(all).toContain('[LOGIN_SUCCESS]');
    expect(all).toContain('alice');
    expect(all).toContain('10.0.0.1');
    expect(all).toContain('srv01');
    expect(all).toContain('1234');
  });

  it('logs login_failure', async () => {
    await request(app)
      .post('/webhook/pamsignal')
      .set(auth())
      .send({
        event: { action: 'login_failure' },
        user: { name: 'bob' },
        source: { ip: '1.2.3.4' },
        host: { hostname: 'srv' },
        pamsignal: {},
      });
    const all = lines().join('\n');
    expect(all).toContain('[LOGIN_FAILED]');
    expect(all).toContain('bob');
  });

  it('logs brute_force_detected', async () => {
    await request(app)
      .post('/webhook/pamsignal')
      .set(auth())
      .send({
        event: { action: 'brute_force_detected' },
        source: { ip: '203.0.113.50' },
        pamsignal: { attempts: 12, window_sec: 300 },
      });
    const all = lines().join('\n');
    expect(all).toContain('[BRUTE_FORCE]');
    expect(all).toContain('12');
    expect(all).toContain('203.0.113.50');
    expect(all).toContain('300');
  });

  it('logs session_opened', async () => {
    await request(app)
      .post('/webhook/pamsignal')
      .set(auth())
      .send({
        event: { action: 'session_opened' },
        user: { name: 'alice' },
        host: { hostname: 'srv' },
        pamsignal: {},
      });
    expect(lines().join('\n')).toContain('[SESSION_OPEN]');
  });

  it('logs session_closed', async () => {
    await request(app)
      .post('/webhook/pamsignal')
      .set(auth())
      .send({
        event: { action: 'session_closed' },
        user: { name: 'alice' },
        host: { hostname: 'srv' },
        pamsignal: {},
      });
    expect(lines().join('\n')).toContain('[SESSION_CLOSE]');
  });

  it('logs UNKNOWN_EVENT for unrecognized actions', async () => {
    await request(app)
      .post('/webhook/pamsignal')
      .set(auth())
      .send({
        event: { action: 'totally_unknown_xyz' },
        pamsignal: {},
      });
    const all = lines().join('\n');
    expect(all).toContain('[UNKNOWN_EVENT]');
    expect(all).toContain('totally_unknown_xyz');
  });

  it('neutralizes log injection: newline, ANSI escape, NUL, DEL', async () => {
    const attack = 'admin\nFAKE\x1b[31m\x00\x7fend';
    await request(app)
      .post('/webhook/pamsignal')
      .set(auth())
      .send({
        event: { action: 'login_success' },
        user: { name: attack },
        pamsignal: {},
      });
    // Each console.log call emits exactly one log line. The control bytes
    // must not appear inside any emitted argument.
    const ls = lines();
    for (const ln of ls) {
      expect(ln).not.toContain('\n');
      expect(ln).not.toContain('\x1b');
      expect(ln).not.toContain('\x00');
      expect(ln).not.toContain('\x7f');
    }
    // Exactly one LOGIN_SUCCESS line — attacker could not inject a second.
    const successLines = ls.filter((l) => l.includes('[LOGIN_SUCCESS]'));
    expect(successLines).toHaveLength(1);
  });
});

// =============================================================================
// safe helper (the primitive behind log-injection defense)
// =============================================================================

describe('safe()', () => {
  it('passes safe ASCII through unchanged', () => {
    expect(safe('alice')).toBe('alice');
    expect(safe('192.168.1.1')).toBe('192.168.1.1');
    expect(safe('')).toBe('');
  });

  it.each([
    ['a\nb', 'a?b'],
    ['a\rb', 'a?b'],
    ['a\tb', 'a?b'],
    ['a\x00b', 'a?b'],
    ['\x1b[31m', '?[31m'],
    ['\x7f', '?'],
  ])('replaces control char in %p → %p', (raw, expected) => {
    expect(safe(raw)).toBe(expected);
  });

  it('replaces every control byte 0x00–0x1f and 0x7f', () => {
    for (let i = 0; i < 32; i++) {
      expect(safe(String.fromCharCode(i))).toBe('?');
    }
    expect(safe('\x7f')).toBe('?');
  });

  it('caps output at 200 chars', () => {
    const out = safe('A'.repeat(1000));
    expect(out.length).toBe(200);
    expect(out).toBe('A'.repeat(200));
  });

  it('handles null and undefined', () => {
    expect(safe(null)).toBe('null');
    expect(safe(undefined)).toBe('undefined');
  });

  it.each([0, 12345, true, false, 3.14])('handles non-string scalar %p', (v) => {
    expect(safe(v)).toBe(String(v));
  });

  it('preserves non-ASCII Unicode (accents, CJK, emoji)', () => {
    expect(safe('café')).toBe('café');
    expect(safe('日本語')).toBe('日本語');
    expect(safe('🔥')).toBe('🔥');
  });
});

// =============================================================================
// safeEqual helper (constant-time string compare)
// =============================================================================

describe('safeEqual()', () => {
  it('returns true for equal strings', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('', '')).toBe(true);
  });

  it('returns false for different strings of equal length', () => {
    expect(safeEqual('abc', 'xyz')).toBe(false);
    expect(safeEqual('a', 'b')).toBe(false);
  });

  it('returns false for strings of different lengths', () => {
    expect(safeEqual('abc', 'abcd')).toBe(false);
    expect(safeEqual('abcd', 'abc')).toBe(false);
    expect(safeEqual('', 'a')).toBe(false);
    expect(safeEqual('a', '')).toBe(false);
  });

  it('handles multi-byte UTF-8 correctly', () => {
    expect(safeEqual('café', 'café')).toBe(true);
    // Different content, same UTF-8 byte length:
    expect(safeEqual('café', 'cafX')).toBe(false);
  });
});
