#!/usr/bin/env python3
"""GoProxy: tiny authenticated reverse proxy for a rotating Cloudflare Quick Tunnel."""

from __future__ import annotations

import argparse
import hmac
import http.client
import json
import logging
import os
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

LOG = logging.getLogger("goproxy")
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
}


class RelayState:
    def __init__(self, state_file: Path, secret_file: Path, allowed_suffix: str):
        self.state_file = state_file
        self.secret_file = secret_file
        self.allowed_suffix = allowed_suffix.lower()
        self.lock = threading.RLock()
        self.target = ""
        self.updated_at = 0.0
        self.secret = secret_file.read_text(encoding="utf-8").strip()
        if not self.secret:
            raise RuntimeError("registration secret is empty")
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            target = raw.get("target", "")
            updated = float(raw.get("updated_at", 0))
            if target:
                self._validate_target(target)
                self.target = target.rstrip("/")
                self.updated_at = updated
        except FileNotFoundError:
            return
        except Exception as exc:
            LOG.warning("Ignoring invalid state file: %s", exc)

    def _validate_target(self, target: str) -> None:
        parsed = urlsplit(target)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("target must be an https URL")
        host = parsed.hostname.lower()
        if self.allowed_suffix and not host.endswith(self.allowed_suffix):
            raise ValueError(f"target host must end with {self.allowed_suffix}")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("target must not contain credentials, query, or fragment")

    def register(self, target: str) -> None:
        self._validate_target(target)
        target = target.rstrip("/")
        now = time.time()
        payload = {"target": target, "updated_at": now}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="state.", suffix=".json", dir=self.state_file.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, separators=(",", ":"))
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.state_file)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
        with self.lock:
            self.target = target
            self.updated_at = now

    def snapshot(self) -> tuple[str, float]:
        with self.lock:
            return self.target, self.updated_at

    def authorized(self, supplied: str) -> bool:
        return bool(supplied) and hmac.compare_digest(supplied, self.secret)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "GoProxy/0.2"

    @property
    def state(self) -> RelayState:
        return self.server.relay_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        LOG.info("%s %s", self.client_address[0], fmt % args)

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self) -> str:
        value = self.headers.get("Authorization", "")
        if value.lower().startswith("bearer "):
            return value[7:].strip()
        return ""

    def _register(self) -> None:
        if not self.state.authorized(self._bearer()):
            self._json(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > 8192:
                raise ValueError("invalid body length")
            data = json.loads(self.rfile.read(length))
            target = str(data.get("target", "")).strip()
            self.state._validate_target(target)
            parsed = urlsplit(target)
            try:
                socket.getaddrinfo(
                    parsed.hostname,
                    parsed.port or 443,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
            except socket.gaierror as exc:
                LOG.info("Refusing unresolved upstream %s: %s", parsed.hostname, exc)
                self._json(503, {"ok": False, "error": "target_dns_unresolved"})
                return
            self.state.register(target)
            LOG.info("Registered new upstream %s", parsed.hostname)
            self._json(200, {"ok": True, "registered": True})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})

    def _health(self) -> None:
        target, updated = self.state.snapshot()
        parsed = urlsplit(target) if target else None
        self._json(200, {
            "ok": True,
            "service": "goproxy",
            "upstream_registered": bool(target),
            "upstream_host": parsed.hostname if parsed else None,
            "updated_at": updated or None,
        })

    def _proxy(self) -> None:
        target, _ = self.state.snapshot()
        if not target:
            self._json(503, {"ok": False, "error": "upstream_not_registered"})
            return

        base = urlsplit(target)
        incoming_path = self.path if self.path.startswith("/") else "/" + self.path
        base_path = base.path.rstrip("/")
        upstream_path = base_path + incoming_path

        length_header = self.headers.get("Content-Length")
        body = None
        if length_header:
            length = int(length_header)
            if length > 64 * 1024 * 1024:
                self._json(413, {"ok": False, "error": "request_too_large"})
                return
            body = self.rfile.read(length)

        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            if key.lower() not in HOP_HEADERS and key.lower() != "host":
                headers[key] = value
        headers["Host"] = base.netloc
        headers["X-GoProxy-Forwarded-For"] = self.client_address[0]

        conn = http.client.HTTPSConnection(
            base.hostname,
            base.port or 443,
            timeout=310,
            context=ssl.create_default_context(),
        )
        try:
            conn.request(self.command, upstream_path, body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status, resp.reason)
            has_length = False
            for key, value in resp.getheaders():
                lower = key.lower()
                if lower in HOP_HEADERS:
                    continue
                if lower == "content-length":
                    has_length = True
                self.send_header(key, value)
            self.send_header("Via", "1.1 GoProxy")
            if not has_length:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception as exc:
            LOG.error("Upstream request failed: %s", exc)
            if not self.wfile.closed:
                try:
                    self._json(502, {"ok": False, "error": "upstream_unavailable"})
                except Exception:
                    pass
        finally:
            conn.close()

    def do_GET(self) -> None:
        if self.path == "/health":
            self._health()
        else:
            self._proxy()

    def do_HEAD(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        if self.path == "/admin/register":
            self._register()
        else:
            self._proxy()

    def do_PUT(self) -> None:
        self._proxy()

    def do_PATCH(self) -> None:
        self._proxy()

    def do_DELETE(self) -> None:
        self._proxy()

    def do_OPTIONS(self) -> None:
        self._proxy()


class RelayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, relay_state: RelayState):
        super().__init__(address, handler)
        self.relay_state = relay_state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default=os.getenv("GOPROXY_LISTEN", "127.0.0.1:8787"))
    parser.add_argument("--state", default=os.getenv("GOPROXY_STATE", "/home/crazytaxzi/GoProxy/state/relay.json"))
    parser.add_argument("--secret-file", default=os.getenv("GOPROXY_SECRET_FILE", "/home/crazytaxzi/GoProxy/state/register.secret"))
    parser.add_argument("--allowed-suffix", default=os.getenv("GOPROXY_ALLOWED_SUFFIX", ".trycloudflare.com"))
    args = parser.parse_args()

    host, port_text = args.listen.rsplit(":", 1)
    state = RelayState(Path(args.state), Path(args.secret_file), args.allowed_suffix)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = RelayHTTPServer((host, int(port_text)), Handler, state)
    LOG.info("GoProxy listening on %s:%s", host, port_text)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
