import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';

import * as dotenv from 'dotenv';
// Load environment variables before anything else
dotenv.config();

import app from './app';

const PORT = Number(process.env.PORT) || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const tlsKeyPath = process.env.TLS_KEY_PATH;
const tlsCertPath = process.env.TLS_CERT_PATH;

let server: http.Server | https.Server;
let scheme: 'http' | 'https' = 'http';

if (tlsKeyPath && tlsCertPath) {
  const opts: https.ServerOptions = {
    key: fs.readFileSync(tlsKeyPath),
    cert: fs.readFileSync(tlsCertPath),
  };
  if (process.env.TLS_CLIENT_CA_PATH) {
    opts.ca = fs.readFileSync(process.env.TLS_CLIENT_CA_PATH);
  }
  if (process.env.TLS_REQUIRE_CLIENT_CERT === 'true') {
    if (!opts.ca) {
      console.warn(
        '⚠️  TLS_REQUIRE_CLIENT_CERT=true but TLS_CLIENT_CA_PATH is unset — ' +
        'clients will be validated against the default trust store, which is ' +
        'almost certainly not what you want for an internal-PKI deployment.'
      );
    }
    opts.requestCert = true;
    opts.rejectUnauthorized = true;
  }
  server = https.createServer(opts, app);
  scheme = 'https';
} else {
  server = http.createServer(app);
}

server.listen(PORT, () => {
  if (scheme === 'https') {
    const mtls = process.env.TLS_REQUIRE_CLIENT_CERT === 'true';
    console.log(
      `🔐 PAMSignal Webhook Receiver listening on https://localhost:${PORT}/webhook/pamsignal` +
      (mtls ? ' (mTLS — client cert required)' : '')
    );
  } else {
    console.log(`🚀 PAMSignal Webhook Receiver listening on http://localhost:${PORT}/webhook/pamsignal`);
  }

  if (!WEBHOOK_SECRET) {
    console.log('⚠️  WARNING: Running without Bearer authentication. Set WEBHOOK_SECRET in .env');
  }
});

export { server };
