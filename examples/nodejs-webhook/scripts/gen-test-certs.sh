#!/bin/bash
# Generate a self-signed CA, server cert, and client cert for local end-to-end
# testing of the mTLS path. NOT FOR PRODUCTION — production deployments use
# cert-manager, certbot, systemd-creds, or whatever cert pipeline the operator
# already runs.
#
# Usage:
#   ./scripts/gen-test-certs.sh [output-dir]
#
# Default output dir is ./certs/. After running:
#
#   - certs/ca.crt        — root CA the server uses to validate clients
#   - certs/ca.key        — root CA private key (don't ship this anywhere)
#   - certs/server.crt    — server cert with CN=localhost
#   - certs/server.key    — server private key (mode 0600)
#   - certs/client.crt    — client cert with CN=pamsignal-client
#   - certs/client.key    — client private key (mode 0600)
#
# Then in this example's .env:
#   TLS_KEY_PATH=./certs/server.key
#   TLS_CERT_PATH=./certs/server.crt
#   TLS_CLIENT_CA_PATH=./certs/ca.crt
#   TLS_REQUIRE_CLIENT_CERT=true
#
# And in pamsignal.conf:
#   webhook_url = https://localhost:3000/webhook/pamsignal
#   webhook_client_cert = /absolute/path/to/certs/client.crt
#   webhook_client_key  = /absolute/path/to/certs/client.key
#   webhook_ca_bundle   = /absolute/path/to/certs/ca.crt

set -euo pipefail

out="${1:-./certs}"
days="${CERT_DAYS:-365}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl not found in PATH" >&2
  exit 1
fi

mkdir -p "$out"
cd "$out"

# Internal CA — self-signed, used to issue both server and client certs below.
openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
  -keyout ca.key -out ca.crt \
  -subj "/CN=PAMSignal Demo Internal CA" 2>/dev/null

# Server cert — CN=localhost so Node's https client accepts the SAN.
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days "$days" \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null

# Client cert — what pamsignal will present in the TLS handshake.
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=pamsignal-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days "$days" 2>/dev/null

# Clean up CSRs and serial — only the .crt and .key files matter to operators.
rm -f server.csr client.csr ca.srl

# Tighten permissions on private keys. pamsignal will additionally refuse to
# load webhook_client_key if it's group/world-readable, so we mode 0600 to
# match.
chmod 600 ca.key server.key client.key
chmod 644 ca.crt server.crt client.crt

cd - >/dev/null

echo "Generated test certs under $out/:"
echo "  CA:      $out/ca.crt + $out/ca.key"
echo "  Server:  $out/server.crt + $out/server.key (CN=localhost)"
echo "  Client:  $out/client.crt + $out/client.key (CN=pamsignal-client)"
echo ""
echo "Next:"
echo "  1. Copy .env.example to .env and uncomment the TLS_* block."
echo "  2. Set webhook_client_cert / webhook_client_key / webhook_ca_bundle"
echo "     in /etc/pamsignal/pamsignal.conf to absolute paths under $out/."
echo "  3. npm run dev   (or npm run build && npm start)"
