#!/usr/bin/env bash
set -euo pipefail

PROJECT="${GOPROXY_GATEWAY_PROJECT:-/home/crazytaxzi/Neon_Wreckers_TTV_Overlay}"
CONTAINER="${GOPROXY_GATEWAY_CONTAINER:-neon-wreckers-gateway-1}"
PORT="${GOPROXY_PORT:-8787}"
PATCHER="/home/crazytaxzi/GoProxy/gateway_patch.py"

root() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

python3 "$PATCHER" --project "$PROJECT"
cd "$PROJECT"
root docker compose config >/dev/null

for _ in {1..30}; do
  if root docker inspect "$CONTAINER" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
root docker inspect "$CONTAINER" >/dev/null

public_host="$(sed -n 's/^PUBLIC_HOST=//p' .env | tail -n1 | tr -d '\r\"')"
gateway_ip="$(root docker inspect "$CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}')"
network_name="$(root docker inspect "$CONTAINER" --format '{{range $name, $cfg := .NetworkSettings.Networks}}{{$name}}{{end}}')"
subnet="$(root docker network inspect "$network_name" --format '{{(index .IPAM.Config 0).Subnet}}')"
bridge_if="$(ip -o -4 addr show | awk -v target="$gateway_ip" 'index($4,target"/")==1 {print $2; exit}')"

test -n "$public_host"
test -n "$gateway_ip"
test -n "$subnet"
test -n "$bridge_if"

if command -v ufw >/dev/null 2>&1 && root ufw status | grep -q '^Status: active'; then
  root ufw allow in on "$bridge_if" proto tcp from "$subnet" to "$gateway_ip" port "$PORT" comment 'GoProxy Docker bridge' >/dev/null
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed "s/\${PUBLIC_HOST}/${public_host}/g; s/host\.docker\.internal/${gateway_ip}/g" \
  infrastructure/gateway/nginx.conf.template > "$tmp"
root docker exec -i "$CONTAINER" sh -c 'cat > /etc/nginx/conf.d/default.conf' < "$tmp"
root docker exec "$CONTAINER" nginx -t >/dev/null
root docker exec "$CONTAINER" nginx -s reload >/dev/null
root docker exec "$CONTAINER" sh -lc "wget -T 5 -q -O - http://${gateway_ip}:${PORT}/health >/dev/null"

echo "gateway_sync=ok public_host=$public_host gateway_ip=$gateway_ip"
