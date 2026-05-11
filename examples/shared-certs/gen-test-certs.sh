#!/bin/bash
# Generate a self-signed CA, server cert, and client cert for local end-to-end
# testing of the mTLS path. NOT FOR PRODUCTION — production deployments use
# cert-manager, certbot, systemd-creds, or whatever cert pipeline the operator
# already runs.
#
# Single source of truth for the example mTLS setup. The Python receiver, the
# Node receiver, and the Bruno collection all symlink their `certs/` dir to
# this directory, so generating once here populates all three at the same
# time.
#
# Usage:
#   cd examples/shared-certs/
#   ./gen-test-certs.sh                 # writes into this directory
#   ./gen-test-certs.sh /tmp/mycerts    # or override the output dir
#
# After running, this directory will contain:
#
#   - ca.crt        — root CA the server uses to validate clients
#   - ca.key        — root CA private key (don't ship this anywhere)
#   - server.crt    — server cert with CN=localhost, SAN=DNS:localhost,IP:127.0.0.1
#   - server.key    — server private key (mode 0600)
#   - client.crt    — client cert with CN=pamsignal-client
#   - client.key    — client private key (mode 0600)
#
# Then in either example's .env:
#   TLS_KEY_PATH=./certs/server.key
#   TLS_CERT_PATH=./certs/server.crt
#   TLS_CLIENT_CA_PATH=./certs/ca.crt
#   TLS_REQUIRE_CLIENT_CERT=true
#
# And in pamsignal.conf:
#   webhook_url = https://127.0.0.1:3000/webhook/pamsignal
#   webhook_client_cert = /absolute/path/to/examples/shared-certs/client.crt
#   webhook_client_key  = /absolute/path/to/examples/shared-certs/client.key
#   webhook_ca_bundle   = /absolute/path/to/examples/shared-certs/ca.crt

set -euo pipefail

# Default to writing into the directory this script lives in — that is the
# `examples/shared-certs/` dir consumed via symlinks by the three example
# projects.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-$script_dir}"
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

# Server cert — CN=localhost so https clients accept the SAN.
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days "$days" \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null

# Client cert — what pamsignal (and Bruno) presents in the TLS handshake.
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
echo "  Server:  $out/server.crt + $out/server.key (CN=localhost, SAN=127.0.0.1)"
echo "  Client:  $out/client.crt + $out/client.key (CN=pamsignal-client)"
echo ""
echo "Both example receivers and the Bruno collection consume this directory"
echo "via the certs/ symlink — restart any running receiver to pick up the"
echo "new server.crt / server.key."
