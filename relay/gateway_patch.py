#!/usr/bin/env python3
"""Idempotently wire GoProxy into the existing Neon Wreckers nginx gateway."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

START = "  # BEGIN GOPROXY RELAY"
END = "  # END GOPROXY RELAY"

NGINX_BLOCK = r'''  # BEGIN GOPROXY RELAY
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
