#!/bin/sh
# Self-signed test certificate (SHA-256, so tls-server-end-point uses SHA-256).
set -eu
cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout certs/server.key -out certs/server.pem \
  -subj "/CN=app.corp.example" \
  -addext "subjectAltName=DNS:localhost,DNS:app.corp.example,IP:127.0.0.1" 2>/dev/null
echo "wrote certs/server.pem and certs/server.key"
