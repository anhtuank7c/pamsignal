/**
 * Integration tests over real HTTP transport.
 *
 * Spins up an http.createServer on a kernel-picked free port and exercises
 * the webhook with the built-in `node:http` client — the same path
 * PAMSignal's curl fork+exec uses. Proves the in-process behavior covered
 * by webhook.test.ts survives a real HTTP roundtrip (headers, body
 * framing, error status codes, content negotiation).
 *
 * mTLS-specific transport behavior lives in mtls.test.ts.
 */

import * as http from 'node:http';
import { AddressInfo } from 'node:net';

import app from '../src/app';

const SECRET = 'integration-secret';

const VALID_PAYLOAD = {
  event: { action: 'brute_force_detected' },
  source: { ip: '203.0.113.50' },
  pamsignal: { attempts: 12, window_sec: 300 },
};

let server: http.Server;
let port: number;

beforeAll((done) => {
  process.env.WEBHOOK_SECRET = SECRET;
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});

  server = http.createServer(app);
  server.listen(0, '127.0.0.1', () => {
    port = (server.address() as AddressInfo).port;
    done();
  });
});

afterAll((done) => {
  jest.restoreAllMocks();
  delete process.env.WEBHOOK_SECRET;
  server.close(() => done());
});

interface Response {
  status: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}

function send(
  body: string | Buffer,
  headers: Record<string, string>,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: '/webhook/pamsignal',
        headers: {
          'Content-Length': String(buf.length),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
            headers: res.headers,
          }),
        );
      },
    );
    req.on('error', reject);
    req.write(buf);
    req.end();
  });
}

function sendJson(payload: unknown, extraHeaders: Record<string, string> = {}): Promise<Response> {
  return send(JSON.stringify(payload), {
    'Content-Type': 'application/json',
    ...extraHeaders,
  });
}

function authHeader(): Record<string, string> {
  return { Authorization: `Bearer ${SECRET}` };
}

// =============================================================================
// Happy path
// =============================================================================

describe('Happy path', () => {
  it('valid request returns 200', async () => {
    const r = await sendJson(VALID_PAYLOAD, authHeader());
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.status).toBe('success');
    expect(body.message).toBe('Event received');
  });

  it('response Content-Type is JSON', async () => {
    const r = await sendJson(VALID_PAYLOAD, authHeader());
    expect(r.headers['content-type']).toMatch(/^application\/json/);
  });
});

// =============================================================================
// Authentication over real transport
// =============================================================================

describe('Authentication over HTTP', () => {
  it('no token → 401', async () => {
    const r = await sendJson(VALID_PAYLOAD);
    expect(r.status).toBe(401);
    expect(JSON.parse(r.body).error).toBe('Unauthorized: Invalid or missing token');
  });

  it('wrong token → 401', async () => {
    const r = await sendJson(VALID_PAYLOAD, { Authorization: 'Bearer not-the-secret' });
    expect(r.status).toBe(401);
  });

  it('wrong scheme → 401', async () => {
    const r = await sendJson(VALID_PAYLOAD, { Authorization: `Basic ${SECRET}` });
    expect(r.status).toBe(401);
  });
});

// =============================================================================
// Defenses over real transport
// =============================================================================

describe('Defenses over HTTP', () => {
  it('wrong Content-Type → 415', async () => {
    const r = await send('this is not json', {
      ...authHeader(),
      'Content-Type': 'text/plain',
    });
    expect(r.status).toBe(415);
  });

  it('oversize body → 413', async () => {
    // 70 KB body, above the 64 KB express.json limit.
    const big = 'A'.repeat(70 * 1024);
    const r = await sendJson({ event: { action: 'x' }, pamsignal: {}, pad: big }, authHeader());
    expect(r.status).toBe(413);
  });

  it('invalid payload shape → 400', async () => {
    const r = await sendJson({}, authHeader());
    expect(r.status).toBe(400);
    expect(JSON.parse(r.body).error).toBe('Bad Request: Invalid payload format');
  });

  it('log injection payload does not crash server', async () => {
    // Control chars in every string field. The server must accept the
    // request and return 200 — the unit-test suite separately verifies
    // that the actual console output is sanitized.
    const attack = 'alice\n\x1b[31mFAKE\x00\x7f';
    const r = await sendJson(
      {
        event: { action: 'login_success' },
        user: { name: attack },
        source: { ip: attack },
        host: { hostname: attack },
        process: { pid: attack },
        pamsignal: {},
      },
      authHeader(),
    );
    expect(r.status).toBe(200);
  });
});

// =============================================================================
// Event dispatch over real transport (every action type returns 200)
// =============================================================================

describe('Event dispatch over HTTP', () => {
  it.each([
    'login_success',
    'login_failure',
    'brute_force_detected',
    'session_opened',
    'session_closed',
    'totally_unknown_xyz',
  ])('action=%s → 200', async (action) => {
    const r = await sendJson(
      {
        event: { action },
        user: { name: 'alice' },
        source: { ip: '1.2.3.4' },
        host: { hostname: 'srv' },
        process: { pid: 1234 },
        pamsignal: { attempts: 1, window_sec: 60 },
      },
      authHeader(),
    );
    expect(r.status).toBe(200);
  });
});
