#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DIR/certs" "$DIR/run"
chmod 777 "$DIR/run"

format_colon_serial() {
  local raw="$1"
  raw="${raw#serial=}"
  raw="$(echo "$raw" | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')"
  echo "$raw" | sed 's/../&:/g; s/:$//'
}

if [[ ! -f "$DIR/certs/hello-world.pem" ]] || [[ "${1:-}" == "--reset" ]]; then
  echo "[aegis-haproxy] Generating initial 15-day self-signed X.509 certificate for CN=hello.internal..."
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 15 \
    -subj "/CN=hello.internal" \
    -keyout "$DIR/certs/initial.key" \
    -out "$DIR/certs/initial.crt" 2>/dev/null

  cat "$DIR/certs/initial.crt" "$DIR/certs/initial.key" > "$DIR/certs/hello-world.pem"
  chmod 600 "$DIR/certs/hello-world.pem"
  rm -f "$DIR/certs/initial.crt" "$DIR/certs/initial.key"

  RAW_SERIAL="$(openssl x509 -in "$DIR/certs/hello-world.pem" -noout -serial)"
  COLON_SERIAL="$(format_colon_serial "$RAW_SERIAL")"
  END_DATE_RAW="$(openssl x509 -in "$DIR/certs/hello-world.pem" -noout -enddate | cut -d= -f2)"
  EXPIRY_ISO="$(date -u -d "$END_DATE_RAW" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "2026-11-04T00:00:00Z")"

  if [[ -f "$DIR/catalog-info.yaml" ]]; then
    sed -i "s|resiliency.idp/cert-version:.*|resiliency.idp/cert-version: \"v1 (Serial: ${COLON_SERIAL})\"|" "$DIR/catalog-info.yaml"
    sed -i "s|resiliency.idp/cert-expiry:.*|resiliency.idp/cert-expiry: \"${EXPIRY_ISO}\"|" "$DIR/catalog-info.yaml"
    sed -i "s|resiliency.idp/days-remaining:.*|resiliency.idp/days-remaining: \"15\"|" "$DIR/catalog-info.yaml"
    sed -i "s|resiliency.idp/cert-status:.*|resiliency.idp/cert-status: \"Warning\"|" "$DIR/catalog-info.yaml"
  fi
fi

echo "[aegis-haproxy] Building container image localhost/aegis-haproxy-sandbox:latest..."
podman build -t localhost/aegis-haproxy-sandbox:latest "$DIR"

echo "[aegis-haproxy] Starting container haproxy-sandbox..."
podman rm -f haproxy-sandbox 2>/dev/null || true
podman run -d --name haproxy-sandbox \
  -p 8443:8443 \
  -p 8088:8080 \
  -v "$DIR/certs:/etc/haproxy/certs:Z" \
  -v "$DIR/run:/var/run/haproxy:Z" \
  -v "$DIR/haproxy.cfg:/etc/haproxy/haproxy.cfg:ro,Z" \
  localhost/aegis-haproxy-sandbox:latest

echo "[aegis-haproxy] Waiting for https://127.0.0.1:8443/healthz..."
for i in $(seq 1 20); do
  if curl -sk https://127.0.0.1:8443/healthz | grep -q '"status":"ok"'; then
    echo "[aegis-haproxy] Sandbox is healthy on https://127.0.0.1:8443"
    exit 0
  fi
  sleep 0.5
done

echo "[aegis-haproxy] ERROR: HAProxy sandbox failed to respond on https://127.0.0.1:8443/healthz" >&2
podman logs haproxy-sandbox >&2 || true
exit 1
