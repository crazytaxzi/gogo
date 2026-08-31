#!/usr/bin/env python3
"""Idempotently wire GoProxy and its dedicated TLS hostname into the existing Nginx gateway."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

PUBLIC_HOST = "gomcp-8-235-7-248.nip.io"
START = "  # BEGIN GOPROXY RELAY"
END = "  # END GOPROXY RELAY"
HOST_START = "# BEGIN GOPROXY DEDICATED HOST"
HOST_END = "# END GOPROXY DEDICATED HOST"

NGINX_BLOCK = r'''  # BEGIN GOPROXY RELAY
  location = /.well-known/oauth-protected-resource {
    proxy_pass http://host.docker.internal:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
  location = /.well-known/oauth-protected-resource/goproxy/mcp {
    proxy_pass http://host.docker.internal:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
  location = /.well-known/oauth-authorization-server/goproxy/oauth {
    proxy_pass http://host.docker.internal:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
  location = /goproxy { return 308 /goproxy/; }
  location ^~ /goproxy/ {
    proxy_pass http://host.docker.internal:8787/;
    proxy_http_version 1.1;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;
    proxy_request_buffering off;
    client_max_body_size 64m;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
  # END GOPROXY RELAY
'''

DEDICATED_HOST_BLOCK = f'''\n{HOST_START}
server {{
  listen 80;
  listen [::]:80;
  server_name {PUBLIC_HOST};
  location / {{ return 308 https://{PUBLIC_HOST}$request_uri; }}
}}

server {{
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name {PUBLIC_HOST};

  ssl_certificate /etc/letsencrypt/live/{PUBLIC_HOST}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/{PUBLIC_HOST}/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;

  add_header Strict-Transport-Security "max-age=31536000" always;
  add_header X-Content-Type-Options nosniff always;
  add_header Referrer-Policy strict-origin-when-cross-origin always;
  client_max_body_size 64m;

  location = /.well-known/oauth-protected-resource {{
    proxy_pass http://host.docker.internal:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }}
  location = /.well-known/oauth-protected-resource/goproxy/mcp {{
    proxy_pass http://host.docker.internal:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }}
  location = /.well-known/oauth-authorization-server/goproxy/oauth {{
    proxy_pass http://host.docker.internal:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }}
  location = /goproxy {{ return 308 /goproxy/; }}
  location ^~ /goproxy/ {{
    proxy_pass http://host.docker.internal:8787/;
    proxy_http_version 1.1;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;
    proxy_request_buffering off;
    client_max_body_size 64m;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }}
}}
{HOST_END}
'''


def backup_once(path: Path) -> None:
    backup = path.with_suffix(path.suffix + ".goproxy.bak")
    if not backup.exists():
        shutil.copy2(path, backup)


def patch_nginx(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    if START in text and END in text:
        before = text.split(START, 1)[0]
        after = text.split(END, 1)[1]
        new = before + NGINX_BLOCK + after.lstrip("\n")
    else:
        anchor = "  location = /admin"
        if anchor not in text:
            anchor = "  location / {"
        if anchor not in text:
            raise RuntimeError("Could not locate nginx insertion point")
        new = text.replace(anchor, NGINX_BLOCK + "\n" + anchor, 1)

    if HOST_START in new and HOST_END in new:
        before = new.split(HOST_START, 1)[0]
        after = new.split(HOST_END, 1)[1]
        new = before.rstrip() + DEDICATED_HOST_BLOCK + after.lstrip("\n")
    else:
        new = new.rstrip() + DEDICATED_HOST_BLOCK

    if new == text:
        return False
    backup_once(path)
    path.write_text(new, encoding="utf-8")
    return True


def patch_compose(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    if "host.docker.internal:host-gateway" in text:
        return False
    start = text.find("\n  gateway:\n")
    end = text.find("\nnetworks:\n", start)
    if start < 0 or end < 0:
        raise RuntimeError("Could not locate gateway service in compose.yaml")
    segment = text[start:end]
    anchor = "    volumes:\n"
    pos = segment.find(anchor)
    if pos < 0:
        raise RuntimeError("Could not locate gateway volumes anchor")
    insert = '    extra_hosts:\n      - "host.docker.internal:host-gateway"\n'
    segment = segment[:pos] + insert + segment[pos:]
    new = text[:start] + segment + text[end:]
    backup_once(path)
    path.write_text(new, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default="/home/crazytaxzi/Neon_Wreckers_TTV_Overlay")
    args = parser.parse_args()
    root = Path(args.project)
    nginx = root / "infrastructure/gateway/nginx.conf.template"
    compose = root / "compose.yaml"
    if not nginx.is_file() or not compose.is_file():
        raise SystemExit("gateway project files not found")
    print(f"nginx_changed={str(patch_nginx(nginx)).lower()}")
    print(f"compose_changed={str(patch_compose(compose)).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
