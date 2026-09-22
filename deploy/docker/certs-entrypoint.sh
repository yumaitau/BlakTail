#!/usr/bin/env bash
# Generate throwaway coordinator certs into /certs when they are missing.
set -euo pipefail

if [ ! -f /certs/coord.crt ] || [ ! -f /certs/ca.crt ] || [ ! -f /certs/coord.key ]; then
  /usr/local/bin/dev-certs /certs
fi

# Caddy terminates console HTTPS. Mint only the missing leaf so an existing
# coordinator CA and leaf stay in place.
if [ ! -f /certs/console.crt ] || [ ! -f /certs/console.key ]; then
  san="DNS:console,DNS:localhost,IP:127.0.0.1"
  if [ -n "${BLAKTAIL_TLS_EXTRA_SAN:-}" ]; then
    san="${san},${BLAKTAIL_TLS_EXTRA_SAN}"
  fi
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /certs/console.key -out /certs/console.csr \
    -subj "/CN=console" \
    -addext "subjectAltName=${san}"
  openssl x509 -req -in /certs/console.csr \
    -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
    -out /certs/console.crt -days 825 \
    -extfile <(printf "subjectAltName=${san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
  rm -f /certs/console.csr
fi

# Coordinator runs as uid 10001; throwaway keys must be readable in-volume.
chmod 644 /certs/ca.crt /certs/coord.crt /certs/ca.key /certs/coord.key /certs/console.crt /certs/console.key
printf 'coordinator certificates are ready in /certs\n'
