#!/usr/bin/env bash
# Live proof for the agent network gateway: a TLS coordinator, the gateway and
# a real Ollama, each in its own container on a private Docker network. Run
# with DOCKER_CONTEXT pointing at a lab Docker host. Everything this starts is
# named agentgw-lab-* and removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
P=agentgw-lab
MODEL="${AGENTGW_LAB_MODEL:-qwen2.5:0.5b}"
RUST_IMAGE="${AGENTGW_LAB_RUST_IMAGE:-rust:1-bookworm}"
RUN_IMAGE=debian:bookworm-slim
WORK="$(mktemp -d)"

cleanup() {
  docker rm -f "$P-coord" "$P-gateway" "$P-ollama" "$P-driver" >/dev/null 2>&1 || true
  docker network rm "$P-net" >/dev/null 2>&1 || true
  docker volume rm -f "$P-bin" "$P-lab" >/dev/null 2>&1 || true
  if [[ -z "${AGENTGW_LAB_KEEP_CACHE:-}" ]]; then
    docker volume rm -f "$P-cargo" "$P-target" "$P-ollama-models" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$P-net" >/dev/null
for volume in bin lab cargo target ollama-models; do docker volume create "$P-$volume" >/dev/null; done

echo "== start ollama and pull $MODEL"
docker run -d --name "$P-ollama" --network "$P-net" -v "$P-ollama-models:/root/.ollama" ollama/ollama >/dev/null
for _ in $(seq 1 30); do docker exec "$P-ollama" ollama list >/dev/null 2>&1 && break; sleep 1; done
docker exec "$P-ollama" ollama pull "$MODEL" >/dev/null 2>&1

echo "== build blaktail-coord and blaktail-agentgw (release, Linux)"
(cd "$ROOT" && git ls-files -z --cached --others --exclude-standard | COPYFILE_DISABLE=1 tar --no-xattrs --null -T - -czf "$WORK/src.tgz")
docker run --rm -i -v "$P-bin:/out" -v "$P-cargo:/usr/local/cargo/registry" -v "$P-target:/target" "$RUST_IMAGE" \
  bash -ceu 'mkdir /src && cd /src && tar xz && CARGO_TARGET_DIR=/target cargo build --quiet --release -p blaktail-coord -p blaktail-agentgw && cp /target/release/blaktail-coord /target/release/blaktail-agentgw /out/' \
  < "$WORK/src.tgz"

echo "== lab CA, coordinator certificate and HMAC secret"
docker run -d --name "$P-driver" --network "$P-net" -v "$P-lab:/lab" "$RUST_IMAGE" sleep infinity >/dev/null
docker exec "$P-driver" bash -ceu '
  apt-get -qq update >/dev/null && apt-get -qq install -y jq >/dev/null
  cd /lab && umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 1 -subj /CN=agentgw-lab-ca 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout coord.key -out coord.csr -subj /CN=agentgw-lab-coord 2>/dev/null
  printf "subjectAltName=DNS:agentgw-lab-coord\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile ext -out coord.crt 2>/dev/null
  openssl rand -hex 32 | tr -d "\n" > hmac
  openssl rand -hex 32 | tr -d "\n" > relay
  chmod 644 ca.crt coord.crt && chmod 600 ca.key coord.key hmac relay
'
docker cp "$ROOT/deploy/homelab/agent-gateway-driver.sh" "$P-driver:/driver.sh"

COORD_ENV=(
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443
  -e BLAKTAIL_DATABASE=/lab/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local
  -e BLAKTAIL_TLS_CERT=/lab/coord.crt -e BLAKTAIL_TLS_KEY=/lab/coord.key
  -e BLAKTAIL_AUTH_HMAC_SECRET_FILE=/lab/hmac -e BLAKTAIL_RELAY_AUTH_SECRET_FILE=/lab/relay
  -e BLAKTAIL_CONSOLE_URL=https://console.agentgw-lab.test
)
echo "== migrate and start the coordinator"
docker run --rm -v "$P-bin:/opt/bt:ro" -v "$P-lab:/lab" "${COORD_ENV[@]}" "$RUN_IMAGE" /opt/bt/blaktail-coord migrate >/dev/null
docker run -d --name "$P-coord" --network "$P-net" -v "$P-bin:/opt/bt:ro" -v "$P-lab:/lab" "${COORD_ENV[@]}" "$RUN_IMAGE" /opt/bt/blaktail-coord serve >/dev/null
for _ in $(seq 1 30); do
  docker exec "$P-driver" curl -fsS --cacert /lab/ca.crt https://agentgw-lab-coord:8443/readyz >/dev/null 2>&1 && break
  sleep 1
done

echo "== organisation, gateway node, providers and agent key"
docker exec -e AGENTGW_LAB_MODEL="$MODEL" "$P-driver" bash /driver.sh setup

echo "== the gateway refuses a public bind"
if out="$(docker run --rm -v "$P-bin:/opt/bt:ro" -v "$P-lab:/lab:ro" "$RUN_IMAGE" /opt/bt/blaktail-agentgw --state-file /lab/state.json --listen 0.0.0.0:8686 2>&1)"; then
  echo "FAIL gateway accepted 0.0.0.0" >&2; exit 1
fi
echo "ok refused: ${out##*: }"

echo "== start the gateway on its container address (lab stand-in for the overlay)"
docker run -d --name "$P-gateway" --network "$P-net" -v "$P-bin:/opt/bt:ro" -v "$P-lab:/lab:ro" "$RUN_IMAGE" \
  sh -c 'exec /opt/bt/blaktail-agentgw --state-file /lab/state.json --coord-ca /lab/ca.crt --allow-private-listen --listen "$(hostname -i | cut -d" " -f1):8686"' >/dev/null
for _ in $(seq 1 30); do
  docker exec "$P-driver" curl -fsS http://agentgw-lab-gateway:8686/healthz >/dev/null 2>&1 && break
  sleep 1
done

echo "== requests through the gateway"
docker exec -e AGENTGW_LAB_MODEL="$MODEL" "$P-driver" bash /driver.sh prove

echo "== gateway log check"
logs="$(docker logs "$P-gateway" 2>&1)"
for secret in "$(docker exec "$P-driver" cat /lab/agent-key)" "$(docker exec "$P-driver" jq -r .node_token /lab/state.json)" sk-lab-offshore-not-real; do
  if grep -qF "$secret" <<<"$logs"; then echo "FAIL a secret reached the gateway log" >&2; exit 1; fi
done
echo "ok gateway log ($(wc -l <<<"$logs") lines) holds no agent key, node token or provider credential"
