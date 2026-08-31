#!/usr/bin/env bash
set -euo pipefail
certbot_bin="$(command -v certbot)"
exec "$certbot_bin" renew --quiet
