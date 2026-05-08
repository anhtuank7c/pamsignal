// Transport-layer test for the mTLS path. The existing webhook.test.ts
// exercises the Bearer middleware via supertest against the Express `app`
// directly (no transport involved); this file proves the construction
// pattern in src/server.ts — `https.createServer({ requestCert: true,
// rejectUnauthorized: true, ca })` + the same `app` — actually rejects
// unauthenticated TLS handshakes and accepts authenticated ones.
//
// Certs are generated fresh under a temp dir at setup via openssl (same
// commands as scripts/gen-test-certs.sh). No fixtures committed to the repo.

import * as fs from 'node:fs';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { AddressInfo } from 'node:net';

import app from '../src/app';

let certDir: string;
let server: https.Server;
let port: number;

const SECRET = 'test-secret';
const VALID_PAYLOAD = {
  event: { action: 'brute_force_detected' },
  source: { ip: '203.0.113.50' },
  pamsignal: { attempts: 12, window_sec: 300 },
};

function openssl(args: string[]): void {
  execFileSync('openssl', args, { stdio: 'pipe' });
}

function genCerts(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
  const cd = (p: string) => path.join(dir, p);

  // CA
  openssl([
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
    '-keyout', cd('ca.key'), '-out', cd('ca.crt'),
    '-subj', '/CN=PAMSignal Test CA',
  ]);

  // Server cert (CN=localhost, SAN=DNS:localhost,IP:127.0.0.1)
  openssl([
    'req', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', cd('server.key'), '-out', cd('server.csr'),
    '-subj', '/CN=localhost',
  ]);
  fs.writeFileSync(cd('server.ext'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  openssl([
    'x509', '-req', '-in', cd('server.csr'),
    '-CA', cd('ca.crt'), '-CAkey', cd('ca.key'), '-CAcreateserial',
    '-out', cd('server.crt'), '-days', '3650',
    '-extfile', cd('server.ext'),
  ]);

  // Client cert
  openssl([
    'req', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', cd('client.key'), '-out', cd('client.csr'),
    '-subj', '/CN=pamsignal-test-client',
  ]);
  openssl([
    'x509', '-req', '-in', cd('client.csr'),
    '-CA', cd('ca.crt'), '-CAkey', cd('ca.key'), '-CAcreateserial',
    '-out', cd('client.crt'), '-days', '3650',
  ]);
}

beforeAll((done) => {
  process.env.WEBHOOK_SECRET = SECRET;
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});

  certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pamsignal-mtls-test-'));
  genCerts(certDir);

  server = https.createServer(
    {
      key: fs.readFileSync(path.join(certDir, 'server.key')),
      cert: fs.readFileSync(path.join(certDir, 'server.crt')),
      ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
      requestCert: true,
      rejectUnauthorized: true,
    },
    app,
  );
  server.listen(0, '127.0.0.1', () => {
    port = (server.address() as AddressInfo).port;
    done();
  });
}, 30000);

afterAll((done) => {
  server.close(() => {
    fs.rmSync(certDir, { recursive: true, force: true });
    jest.restoreAllMocks();
    done();
  });
});

function postWithClientCert(payload: object): Promise<{ status?: number; body?: string; tlsError?: Error }> {
  return new Promise((resolve) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: '/webhook/pamsignal',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${SECRET}`,
        },
        ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
        cert: fs.readFileSync(path.join(certDir, 'client.crt')),
        key: fs.readFileSync(path.join(certDir, 'client.key')),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() })
        );
      },
    );
    req.on('error', (err) => resolve({ tlsError: err }));
    req.write(JSON.stringify(payload));
    req.end();
  });
}

function postWithoutClientCert(payload: object): Promise<{ status?: number; tlsError?: Error }> {
  return new Promise((resolve) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: '/webhook/pamsignal',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${SECRET}`,
        },
        ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
        // Deliberately no `cert` / `key` — server should reject the request.
      },
      (res) => {
        // If we get here, the server let an unauthenticated client through —
        // resolve with the status so the test can fail loudly with the value.
        resolve({ status: res.statusCode });
      },
    );
    req.on('error', (err) => resolve({ tlsError: err }));
    req.write(JSON.stringify(payload));
    req.end();
  });
}

describe('mTLS handshake', () => {
  it('accepts a request with a valid client cert + Bearer token', async () => {
    const { status, body, tlsError } = await postWithClientCert(VALID_PAYLOAD);
    expect(tlsError).toBeUndefined();
    expect(status).toBe(200);
    expect(JSON.parse(body!).status).toBe('success');
  });

  it('rejects the request when no client cert is presented', async () => {
    const { status, tlsError } = await postWithoutClientCert(VALID_PAYLOAD);
    // Server with requestCert+rejectUnauthorized rejects the connection
    // before the request reaches Express. Node surfaces this as ECONNRESET
    // or a TLS-level "alert certificate required" depending on the Node /
    // OpenSSL versions. The exact error code varies; what matters is that
    // the request did not produce an HTTP response.
    expect(status).toBeUndefined();
    expect(tlsError).toBeDefined();
    expect(typeof tlsError?.message).toBe('string');
  });

  it('still validates the Bearer token after a successful handshake', async () => {
    process.env.WEBHOOK_SECRET = 'different-secret';
    const { status, tlsError } = await postWithClientCert(VALID_PAYLOAD);
    expect(tlsError).toBeUndefined();
    // Bearer mismatch — middleware should 401 even though TLS handshake
    // and client cert validation passed.
    expect(status).toBe(401);
    process.env.WEBHOOK_SECRET = SECRET;
  });
});
