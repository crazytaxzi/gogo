#!/usr/bin/env bash
set -euo pipefail
PROJECT=/home/crazytaxzi/Neon_Wreckers_TTV_Overlay
public_host="$(sed -n 's/^PUBLIC_HOST=//p' "$PROJECT/.env" | tail -n1 | tr -d '\r\"')"
test -n "$public_host"
certbot_bin="$(command -v certbot)"
exec "$certbot_bin" renew --cert-name "$public_host" --quiet
