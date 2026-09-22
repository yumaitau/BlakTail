#!/usr/bin/env bash
# Generates a throwaway local CA plus a coord leaf cert for compose quickstarts.
# Production uses real certificates (ACM + NLB/ALB); never reuse these.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:-$ROOT/certs}"

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

mkdir -p "$DIR"
umask 077

# Extra SAN entries for a remote Docker host, e.g. DNS:homelab,IP:192.168.1.19
SAN="DNS:coord,DNS:localhost,IP:127.0.0.1"
if [ -n "${BLAKTAIL_TLS_EXTRA_SAN:-}" ]; then
  SAN="${SAN},${BLAKTAIL_TLS_EXTRA_SAN}"
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$DIR/ca.key" -out "$DIR/ca.crt" -days 3650 \
  -subj "/CN=BlakTail Development CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$DIR/coord.key" -out "$DIR/coord.csr" \
  -subj "/CN=coord" \
  -addext "subjectAltName=${SAN}"

openssl x509 -req -in "$DIR/coord.csr" \
  -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/coord.crt" -days 825 \
  -extfile <(printf "subjectAltName=${SAN}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

rm -f "$DIR/coord.csr"

console_san="DNS:console,DNS:localhost,IP:127.0.0.1"
if [ -n "${BLAKTAIL_TLS_EXTRA_SAN:-}" ]; then
  console_san="${console_san},${BLAKTAIL_TLS_EXTRA_SAN}"
fi
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$DIR/console.key" -out "$DIR/console.csr" \
  -subj "/CN=console" \
  -addext "subjectAltName=${console_san}"
openssl x509 -req -in "$DIR/console.csr" \
  -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/console.crt" -days 825 \
  -extfile <(printf "subjectAltName=${console_san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
rm -f "$DIR/console.csr"
chmod 600 "$DIR/coord.key" "$DIR/ca.key" "$DIR/console.key"
echo "dev certificates written to $DIR (coord.crt, coord.key, console.crt, console.key, ca.crt)"
