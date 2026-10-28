#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

podman build -t localhost/aegis-harbor-sandbox:latest "$DIR"

podman rm -f harbor-registry-sandbox 2>/dev/null || true

podman run -d --name harbor-registry-sandbox -p 8880:8880 localhost/aegis-harbor-sandbox:latest

for i in $(seq 1 10); do
  if curl -sf http://127.0.0.1:8880/api/v2.0/health > /dev/null; then
    echo "Harbor registry sandbox is healthy."
    exit 0
  fi
  sleep 1
done

echo "Harbor registry sandbox failed to become healthy within 10 seconds." >&2
exit 1
