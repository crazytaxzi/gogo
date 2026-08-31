#!/usr/bin/env python3
"""GoProxy: stable OAuth front door for a rotating Cloudflare Quick Tunnel."""

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
from urllib.parse import parse_qs, urlsplit

from oauth import OAuthError, OAuthManager

LOG = logging.getLogger("goproxy")
PUBLIC_ORIGIN = "https://gomcp-8-235-7-248.nip.io"
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
    server_version = "GoProxy/1.1"

    @property
    def state(self) -> RelayState:
        return self.server.relay_state  # type: ignore[attr-defined]

    @property
    def oauth(self) -> OAuthManager:
        return self.server.oauth  # type: ignore[attr-defined]

    @property
    def upstream_secret_file(self) -> Path:
        return self.server.upstream_secret_file  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        LOG.info("%s %s", self.client_address[0], fmt % args)

    def _json(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self) -> str:
        value = self.headers.get("Authorization", "")
        if value.lower().startswith("bearer "):
            return value[7:].strip()
        return ""

    def _read_json(self, max_bytes: int = 65536) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise OAuthError("invalid_request", "Invalid Content-Length") from exc
        if length < 1 or length > max_bytes:
            raise OAuthError("invalid_request", "Invalid request body length")
        try:
            payload = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise OAuthError("invalid_request", "Malformed JSON") from exc
        if not isinstance(payload, dict):
            raise OAuthError("invalid_request", "JSON body must be an object")
        return payload

    def _read_form(self, max_bytes: int = 65536) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise OAuthError("invalid_request", "Invalid Content-Length") from exc
        if length < 1 or length > max_bytes:
            raise OAuthError("invalid_request", "Invalid request body length")
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw, keep_blank_values=True, strict_parsing=False)
        return {key: values[-1] for key, values in parsed.items() if values}

    def _oauth_error(self, exc: OAuthError) -> None:
        self._json(exc.status, {"error": exc.error, "error_description": exc.description})

    def _oauth_register(self) -> None:
        try:
            payload = self._read_json()
            result = self.oauth.register_client(payload)
            self._json(201, result)
        except OAuthError as exc:
            self._oauth_error(exc)

    def _oauth_authorize_get(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        try:
            request_id = self.oauth.begin_authorization(query)
            page = self.oauth.authorization_form(request_id)
            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)
        except OAuthError as exc:
            self._oauth_error(exc)

    def _oauth_authorize_post(self) -> None:
        remote_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",", 1)[0].strip()
        try:
            form = self._read_form()
            request_id = form.get("request_id", "")
            owner_key = form.get("owner_key", "")
            if not self.oauth.login_allowed(remote_ip):
                raise OAuthError("access_denied", "Too many failed authorization attempts", status=429)
            try:
                redirect = self.oauth.approve_authorization(request_id, owner_key)
            except OAuthError as exc:
                if exc.error == "access_denied":
                    self.oauth.note_failed_login(remote_ip)
                    page = self.oauth.authorization_form(request_id, "Authorization key was not accepted.")
                    body = page.encode("utf-8")
                    self.send_response(401)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                raise
            self.send_response(302)
            self.send_header("Location", redirect)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OAuthError as exc:
            self._oauth_error(exc)

    def _oauth_token(self) -> None:
        try:
            form = self._read_form()
            result = self.oauth.token(form)
            self._json(200, result)
        except OAuthError as exc:
            self._oauth_error(exc)

    def _upstream_secret(self) -> str:
        value = self.upstream_secret_file.read_text(encoding="utf-8").strip()
        if not value:
            raise RuntimeError("upstream secret is empty")
        return value

    def _target_ready(self, parsed) -> bool:
        health_path = parsed.path.rstrip("/") + "/health"
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=8,
            context=ssl.create_default_context(),
        )
        try:
            conn.request("GET", health_path, headers={
                "Host": parsed.netloc,
                "User-Agent": "GoProxy/1.1 readiness",
                "Accept": "application/json",
            })
            resp = conn.getresponse()
            body = resp.read(8192)
            if resp.status != 200:
                LOG.info("Upstream readiness %s returned HTTP %s", parsed.hostname, resp.status)
                return False
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                LOG.info("Upstream readiness %s returned non-JSON health", parsed.hostname)
                return False
            return payload.get("ok") is True
        except Exception as exc:
            LOG.info("Upstream readiness %s failed: %s", parsed.hostname, exc)
            return False
        finally:
            conn.close()

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
            if not self._target_ready(parsed):
                self._json(503, {"ok": False, "error": "target_not_ready"})
                return
            self.state.register(target)
            LOG.info("Registered ready upstream %s", parsed.hostname)
            self._json(200, {"ok": True, "registered": True})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})

    def _health(self) -> None:
        target, updated = self.state.snapshot()
        parsed = urlsplit(target) if target else None
        self._json(200, {
            "ok": True,
            "service": "goproxy",
            "oauth": True,
            "issuer": self.oauth.issuer,
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
        is_mcp = urlsplit(incoming_path).path == "/mcp"

        if is_mcp:
            supplied = self._bearer()
            valid = self.oauth.validate_access_token(supplied, self.oauth.resource) if supplied else None
            if not valid:
                self._json(
                    401,
                    {"ok": False, "error": "invalid_token" if supplied else "authorization_required"},
                    {"WWW-Authenticate": self.oauth.bearer_challenge(invalid_token=bool(supplied))},
                )
                return

        length_header = self.headers.get("Content-Length")
        body = None
        if length_header:
            try:
                length = int(length_header)
            except ValueError:
                self._json(400, {"ok": False, "error": "invalid_content_length"})
                return
            if length > 64 * 1024 * 1024:
                self._json(413, {"ok": False, "error": "request_too_large"})
                return
            body = self.rfile.read(length)

        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            lower = key.lower()
            if lower in HOP_HEADERS or lower == "host" or (is_mcp and lower == "authorization"):
                continue
            headers[key] = value
        headers["Host"] = base.netloc
        headers["X-GoProxy-Forwarded-For"] = self.client_address[0]
        if is_mcp:
            try:
                headers["Authorization"] = f"Bearer {self._upstream_secret()}"
            except RuntimeError as exc:
                LOG.error("Cannot proxy authenticated MCP request: %s", exc)
                self._json(503, {"ok": False, "error": "upstream_auth_not_ready"})
                return

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
                if lower in HOP_HEADERS or (is_mcp and lower == "www-authenticate"):
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
        path = urlsplit(self.path).path
        if path == "/health":
            self._health()
        elif path in {
            "/.well-known/oauth-protected-resource/goproxy/mcp",
            "/.well-known/oauth-protected-resource",
        }:
            self._json(200, self.oauth.protected_resource_metadata())
        elif path in {
            "/.well-known/oauth-authorization-server/goproxy/oauth",
            "/oauth/.well-known/oauth-authorization-server",
        }:
            self._json(200, self.oauth.authorization_server_metadata())
        elif path == "/oauth/authorize":
            self._oauth_authorize_get()
        else:
            self._proxy()

    def do_HEAD(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/admin/register":
            self._register()
        elif path == "/oauth/register":
            self._oauth_register()
        elif path == "/oauth/authorize":
            self._oauth_authorize_post()
        elif path == "/oauth/token":
            self._oauth_token()
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

    def __init__(
        self,
        address,
        handler,
        relay_state: RelayState,
        oauth: OAuthManager,
        upstream_secret_file: Path,
    ):
        super().__init__(address, handler)
        self.relay_state = relay_state
        self.oauth = oauth
        self.upstream_secret_file = upstream_secret_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default=os.getenv("GOPROXY_LISTEN", "127.0.0.1:8787"))
    parser.add_argument("--state", default=os.getenv("GOPROXY_STATE", "/home/crazytaxzi/GoProxy/state/relay.json"))
    parser.add_argument("--secret-file", default=os.getenv("GOPROXY_SECRET_FILE", "/home/crazytaxzi/GoProxy/state/register.secret"))
    parser.add_argument("--upstream-secret-file", default=os.getenv("GOPROXY_UPSTREAM_SECRET_FILE", "/home/crazytaxzi/GoProxy/state/upstream.secret"))
    parser.add_argument("--oauth-state", default=os.getenv("GOPROXY_OAUTH_STATE", "/home/crazytaxzi/GoProxy/state/oauth.json"))
    parser.add_argument("--owner-hash-file", default=os.getenv("GOPROXY_OWNER_HASH_FILE", "/home/crazytaxzi/GoProxy/state/owner-token.sha256"))
    parser.add_argument("--public-origin", default=os.getenv("GOPROXY_PUBLIC_ORIGIN", PUBLIC_ORIGIN))
    parser.add_argument("--allowed-suffix", default=os.getenv("GOPROXY_ALLOWED_SUFFIX", ".trycloudflare.com"))
    args = parser.parse_args()

    host, port_text = args.listen.rsplit(":", 1)
    state = RelayState(Path(args.state), Path(args.secret_file), args.allowed_suffix)
    oauth = OAuthManager(Path(args.oauth_state), Path(args.owner_hash_file), args.public_origin)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = RelayHTTPServer(
        (host, int(port_text)),
        Handler,
        state,
        oauth,
        Path(args.upstream_secret_file),
    )
    LOG.info("GoProxy OAuth relay listening on %s:%s issuer=%s", host, port_text, oauth.issuer)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
