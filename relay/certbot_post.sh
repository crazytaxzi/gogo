#!/usr/bin/env bash
set -euo pipefail
PROJECT=/home/crazytaxzi/Neon_Wreckers_TTV_Overlay
cd "$PROJECT"
docker compose up -d gateway
for _ in {1..30}; do
  if docker inspect neon-wreckers-gateway-1 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
/home/crazytaxzi/GoProxy/gateway_sync.sh
