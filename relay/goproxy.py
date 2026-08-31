#!/usr/bin/env python3
"""GoProxy: stable OAuth front door and administrator console for GoMCP."""

from __future__ import annotations

import argparse
import base64
import hmac
import html
import http.client
import json
import logging
import os
import socket
import ssl
import tempfile
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from admin_auth import AdminAuth, AdminAuthError
from oauth import OAuthError, OAuthManager
from tool_policy import ToolPolicy

LOG = logging.getLogger("goproxy")
PUBLIC_ORIGIN = "https://gomcp-8-235-7-248.nip.io"
SESSION_COOKIE = "__Host-gomcp_session"
PRESESSION_COOKIE = "__Host-gomcp_pre"
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
}
PAGE_CSS = """
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
*{box-sizing:border-box}body{margin:0;background:#101114;color:#f3f4f6;min-height:100vh}
a{color:#a7c7ff}main{width:min(1120px,calc(100% - 28px));margin:32px auto 70px}
.card{background:#1a1c21;border:1px solid #30343b;border-radius:14px;padding:20px;margin:14px 0}
.narrow{width:min(520px,calc(100% - 28px));margin:9vh auto}
h1,h2,h3{margin-top:0}p{line-height:1.5;color:#cbd0d7}.muted{color:#9aa2ad;font-size:13px}
label{display:block;font-weight:650;margin:14px 0 6px}input,textarea{width:100%;background:#101216;color:#fff;border:1px solid #454b55;border-radius:9px;padding:11px;font:inherit}
input[type=checkbox]{width:auto;transform:scale(1.2);margin-right:8px}textarea{min-height:90px;resize:vertical}
button,.button{border:0;border-radius:999px;padding:10px 16px;background:#f5f5f5;color:#111;font-weight:750;cursor:pointer;text-decoration:none;display:inline-block}
button.secondary,.button.secondary{background:#323741;color:#fff}.danger{background:#7f1d1d!important;color:#fff!important}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.spread{justify-content:space-between}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.metric{padding:14px;background:#14161a;border:1px solid #2c3037;border-radius:10px}.metric strong{font-size:24px;display:block}
.error,.notice{padding:12px;border-radius:9px;margin:12px 0}.error{background:#491f22;border:1px solid #8d3a42;color:#ffd8dc}.notice{background:#173528;border:1px solid #2f6f51;color:#d6ffe8}
nav{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:18px}nav form{margin:0 0 0 auto}
.tool{padding:16px;border:1px solid #30343b;border-radius:12px;margin:10px 0;background:#15171b}.tool.disabled{opacity:.72}
.toolname{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-weight:800}
.badge{font-size:12px;padding:3px 8px;border-radius:999px;background:#303640;color:#dce6f5}
details{margin-top:10px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0d0f12;padding:12px;border-radius:8px;border:1px solid #282c33}
hr{border:0;border-top:1px solid #30343b;margin:22px 0}
@media(max-width:600px){main{margin-top:18px}.card{padding:16px}}
"""


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
    server_version = "GoProxy/2.0"

    @property
    def state(self) -> RelayState:
        return self.server.relay_state  # type: ignore[attr-defined]

    @property
    def oauth(self) -> OAuthManager:
        return self.server.oauth  # type: ignore[attr-defined]

    @property
    def admin_auth(self) -> AdminAuth:
        return self.server.admin_auth  # type: ignore[attr-defined]

    @property
    def tool_policy(self) -> ToolPolicy:
        return self.server.tool_policy  # type: ignore[attr-defined]

    @property
    def upstream_secret_file(self) -> Path:
        return self.server.upstream_secret_file  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        LOG.info("%s %s", self.client_address[0], fmt % args)

    def _send_bytes(self, status: int, content_type: str, body: bytes,
                    headers: dict[str, str] | None = None,
                    set_cookies: list[str] | None = None,
                    html_page: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if html_page:
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        for value in set_cookies or []:
            self.send_header("Set-Cookie", value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: object, headers: dict[str, str] | None = None) -> None:
        self._send_bytes(status, "application/json; charset=utf-8", json.dumps(payload, separators=(",", ":")).encode("utf-8"), headers=headers)

    def _html(self, status: int, page: str, headers: dict[str, str] | None = None,
              set_cookies: list[str] | None = None) -> None:
        self._send_bytes(status, "text/html; charset=utf-8", page.encode("utf-8"), headers=headers, set_cookies=set_cookies, html_page=True)

    def _redirect(self, location: str, set_cookies: list[str] | None = None) -> None:
        self._send_bytes(302, "text/plain; charset=utf-8", b"", headers={"Location": location}, set_cookies=set_cookies)

    def _page(self, title: str, content: str, narrow: bool = False) -> str:
        klass = "narrow" if narrow else ""
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>{html.escape(title)}</title><style>{PAGE_CSS}</style></head>'
                f'<body><main class="{klass}">{content}</main></body></html>')

    def _message_page(self, title: str, message: str, status: int = 400) -> None:
        content = (f'<section class="card"><h1>{html.escape(title)}</h1><p>{html.escape(message)}</p>'
                   '<p><a class="button secondary" href="/goproxy/login">Go to login</a></p></section>')
        self._html(status, self._page(title, content, narrow=True))

    def _bearer(self) -> str:
        value = self.headers.get("Authorization", "")
        return value[7:].strip() if value.lower().startswith("bearer ") else ""

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
        try:
            raw = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OAuthError("invalid_request", "Form body must be UTF-8") from exc
        parsed = parse_qs(raw, keep_blank_values=True, strict_parsing=False)
        return {key: values[-1] for key, values in parsed.items() if values}

    def _oauth_error(self, exc: OAuthError) -> None:
        self._json(exc.status, {"error": exc.error, "error_description": exc.description})

    def _remote_ip(self) -> str:
        return self.headers.get("X-Real-IP", self.client_address[0]).strip()[:128]

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return ""
        morsel = jar.get(name)
        return morsel.value if morsel else ""

    def _session(self) -> tuple[str, dict | None]:
        token = self._cookie(SESSION_COOKIE)
        return token, self.admin_auth.get_session(token)

    def _session_cookie(self, token: str) -> str:
        return f"{SESSION_COOKIE}={token}; Path=/; Max-Age={self.admin_auth.SESSION_TTL}; Secure; HttpOnly; SameSite=Lax"

    @staticmethod
    def _expire_cookie(name: str) -> str:
        return f"{name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"

    def _pre_cookie(self, token: str) -> str:
        return f"{PRESESSION_COOKIE}={token}; Path=/; Max-Age={self.admin_auth.PRESESSION_TTL}; Secure; HttpOnly; SameSite=Lax"

    def _same_origin_post(self) -> bool:
        expected = self.oauth.public_origin
        origin = self.headers.get("Origin", "")
        if origin:
            return origin.rstrip("/") == expected
        referer = self.headers.get("Referer", "")
        if referer:
            parsed = urlsplit(referer)
            return f"{parsed.scheme}://{parsed.netloc}".rstrip("/") == expected
        return False

    def _require_same_origin(self) -> None:
        if not self._same_origin_post():
            raise OAuthError("invalid_request", "Cross-site form submission rejected", status=403)

    def _login_page(self, csrf: str, request_id: str = "", error: str = "") -> str:
        try:
            username = str(self.admin_auth.credential_status()["username"])
        except AdminAuthError:
            username = "admin"
        error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
        request_html = f'<input type="hidden" name="request_id" value="{html.escape(request_id, quote=True)}">' if request_id else ""
        content = f'''<section class="card"><h1>GoMCP Admin Login</h1><p>Sign in to manage GamePC MCP access and approve ChatGPT authorization requests.</p>{error_html}
<form method="post" action="/goproxy/login" autocomplete="on"><input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">{request_html}
<label for="username">Username</label><input id="username" name="username" value="{html.escape(username, quote=True)}" required autocomplete="username" autofocus>
<label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password"><button type="submit">Sign in</button></form>
<p class="muted">HTTPS only. Repeated failed logins are rate limited.</p></section>'''
        return self._page("GoMCP Login", content, narrow=True)

    def _login_get(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        request_id = query.get("request_id", [""])[-1]
        if request_id:
            try:
                self.oauth.get_authorization_request(request_id)
            except OAuthError as exc:
                self._message_page("Authorization unavailable", exc.description, 400)
                return
        _, session = self._session()
        if session:
            try:
                status = self.admin_auth.credential_status()
            except AdminAuthError as exc:
                self._message_page("Login unavailable", str(exc), 503)
                return
            if status["must_change_password"]:
                target = "/goproxy/admin/password?required=1"
                if request_id:
                    target += "&" + urlencode({"request_id": request_id})
                self._redirect(target)
                return
            self._redirect("/goproxy/oauth/authorize?" + urlencode({"request_id": request_id}) if request_id else "/goproxy/admin")
            return
        pre_token, csrf = self.admin_auth.create_pre_session()
        self._html(200, self._login_page(csrf, request_id), set_cookies=[self._pre_cookie(pre_token)])

    def _login_post(self) -> None:
        try:
            self._require_same_origin()
            form = self._read_form(32768)
            request_id = form.get("request_id", "")
            if not self.admin_auth.consume_pre_session(self._cookie(PRESESSION_COOKIE), form.get("csrf", "")):
                raise OAuthError("invalid_request", "Login form expired. Reload and try again.", status=400)
            ok, reason = self.admin_auth.authenticate(form.get("username", ""), form.get("password", ""), self._remote_ip())
            if not ok:
                pre_token, csrf = self.admin_auth.create_pre_session()
                message = "Too many login attempts. Try again later." if reason == "rate_limited" else "Invalid username or password."
                self._html(429 if reason == "rate_limited" else 401, self._login_page(csrf, request_id, message), set_cookies=[self._pre_cookie(pre_token)])
                return
            session_token, _ = self.admin_auth.create_session(self.headers.get("User-Agent", ""))
            cookies = [self._session_cookie(session_token), self._expire_cookie(PRESESSION_COOKIE)]
            status = self.admin_auth.credential_status()
            if status["must_change_password"]:
                target = "/goproxy/admin/password?required=1" + (("&" + urlencode({"request_id": request_id})) if request_id else "")
            elif request_id:
                target = "/goproxy/oauth/authorize?" + urlencode({"request_id": request_id})
            else:
                target = "/goproxy/admin"
            self._redirect(target, cookies)
        except (OAuthError, AdminAuthError) as exc:
            self._message_page("Login failed", exc.description if isinstance(exc, OAuthError) else str(exc), exc.status if isinstance(exc, OAuthError) else 503)

    def _nav(self, session: dict) -> str:
        csrf = html.escape(str(session.get("csrf", "")), quote=True)
        username = html.escape(str(session.get("username", "admin")))
        return f'''<nav><a class="button secondary" href="/goproxy/admin">Tools</a><a class="button secondary" href="/goproxy/admin/password">Password</a><span class="muted">Signed in as {username}</span>
<form method="post" action="/goproxy/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="secondary" type="submit">Log out</button></form></nav>'''

    def _password_page(self, session: dict, request_id: str = "", required: bool = False, error: str = "") -> str:
        error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
        required_html = '<div class="notice">Change the temporary password before authorizing MCP access.</div>' if required else ""
        request_html = f'<input type="hidden" name="request_id" value="{html.escape(request_id, quote=True)}">' if request_id else ""
        content = f'''{self._nav(session)}<section class="card"><h1>Change password</h1>{required_html}{error_html}
<form method="post" action="/goproxy/admin/password" autocomplete="off"><input type="hidden" name="csrf" value="{html.escape(str(session.get("csrf","")), quote=True)}">{request_html}
<label for="current_password">Current password</label><input id="current_password" name="current_password" type="password" required autocomplete="current-password">
<label for="new_password">New password</label><input id="new_password" name="new_password" type="password" minlength="{self.admin_auth.PASSWORD_MIN_CHARS}" required autocomplete="new-password">
<label for="confirm_password">Confirm new password</label><input id="confirm_password" name="confirm_password" type="password" minlength="{self.admin_auth.PASSWORD_MIN_CHARS}" required autocomplete="new-password"><button type="submit">Change password</button></form>
<p class="muted">Changing the password signs out all existing GoMCP admin browser sessions. OAuth refresh tokens are left intact.</p></section>'''
        return self._page("GoMCP Password", content)

    def _password_get(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        request_id = query.get("request_id", [""])[-1]
        required = query.get("required", [""])[-1] == "1"
        _, session = self._session()
        if not session:
            self._redirect("/goproxy/login" + (("?" + urlencode({"request_id": request_id})) if request_id else ""))
            return
        self._html(200, self._password_page(session, request_id, required))

    def _password_post(self) -> None:
        _, session = self._session()
        if not session:
            self._redirect("/goproxy/login")
            return
        form: dict[str, str] = {}
        try:
            self._require_same_origin()
            form = self._read_form(65536)
            if not self.admin_auth.csrf_valid(session, form.get("csrf", "")):
                raise OAuthError("invalid_request", "CSRF validation failed", status=403)
            new_password = form.get("new_password", "")
            if new_password != form.get("confirm_password", ""):
                raise AdminAuthError("New password confirmation does not match")
            self.admin_auth.change_password(str(session["username"]), form.get("current_password", ""), new_password)
            request_id = form.get("request_id", "")
            self.admin_auth.destroy_all_sessions()
            new_token, _ = self.admin_auth.create_session(self.headers.get("User-Agent", ""))
            target = "/goproxy/admin"
            if request_id:
                try:
                    self.oauth.get_authorization_request(request_id)
                    target = "/goproxy/oauth/authorize?" + urlencode({"request_id": request_id})
                except OAuthError:
                    pass
            self._redirect(target, [self._session_cookie(new_token)])
        except (OAuthError, AdminAuthError) as exc:
            self._html(exc.status if isinstance(exc, OAuthError) else 400, self._password_page(session, form.get("request_id", ""), True, exc.description if isinstance(exc, OAuthError) else str(exc)))

    def _logout_post(self) -> None:
        token, session = self._session()
        try:
            self._require_same_origin()
            form = self._read_form(16384)
            if not self.admin_auth.csrf_valid(session, form.get("csrf", "")):
                raise OAuthError("invalid_request", "CSRF validation failed", status=403)
            self.admin_auth.destroy_session(token)
            self._redirect("/goproxy/login", [self._expire_cookie(SESSION_COOKIE)])
        except OAuthError as exc:
            self._message_page("Logout failed", exc.description, exc.status)

    def _oauth_register(self) -> None:
        try:
            self._json(201, self.oauth.register_client(self._read_json()))
        except OAuthError as exc:
            self._oauth_error(exc)

    def _consent_page(self, session: dict, request: dict) -> str:
        scopes = ", ".join(html.escape(str(x)) for x in request.get("scope", []))
        content = f'''{self._nav(session)}<section class="card narrow"><h1>Authorize GoMCP</h1><p><strong>{html.escape(str(request.get("client_name","ChatGPT")))}</strong> is requesting access to the GamePC MCP server.</p><p>Scopes: <span class="badge">{scopes}</span></p>
<form method="post" action="/goproxy/oauth/authorize"><input type="hidden" name="csrf" value="{html.escape(str(session.get("csrf","")), quote=True)}"><input type="hidden" name="request_id" value="{html.escape(str(request["request_id"]), quote=True)}"><div class="row"><button type="submit" name="decision" value="allow">Authorize ChatGPT</button><button class="secondary" type="submit" name="decision" value="deny">Deny</button></div></form></section>'''
        return self._page("Authorize GoMCP", content)

    def _oauth_authorize_get(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        try:
            request_values = query.get("request_id", [])
            if request_values:
                if len(request_values) != 1:
                    raise OAuthError("invalid_request", "Duplicate request_id")
                request_id = request_values[0]
            else:
                request_id = self.oauth.begin_authorization(query)
            request = self.oauth.get_authorization_request(request_id)
            _, session = self._session()
            if not session:
                self._redirect("/goproxy/login?" + urlencode({"request_id": request_id}))
                return
            if self.admin_auth.credential_status()["must_change_password"]:
                self._redirect("/goproxy/admin/password?required=1&" + urlencode({"request_id": request_id}))
                return
            self._html(200, self._consent_page(session, request))
        except (OAuthError, AdminAuthError) as exc:
            self._message_page("Authorization unavailable", exc.description if isinstance(exc, OAuthError) else str(exc), exc.status if isinstance(exc, OAuthError) else 503)

    def _oauth_authorize_post(self) -> None:
        _, session = self._session()
        try:
            self._require_same_origin()
            form = self._read_form()
            request_id = form.get("request_id", "")
            if not session:
                self._redirect("/goproxy/login?" + urlencode({"request_id": request_id}))
                return
            if not self.admin_auth.csrf_valid(session, form.get("csrf", "")):
                raise OAuthError("invalid_request", "CSRF validation failed", status=403)
            self.oauth.get_authorization_request(request_id)
            redirect = self.oauth.deny_authorization(request_id) if form.get("decision") == "deny" else self.oauth.approve_authorization(request_id)
            self._redirect(redirect)
        except OAuthError as exc:
            self._message_page("Authorization failed", exc.description, exc.status)

    def _oauth_token(self) -> None:
        try:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise OAuthError("invalid_request", "Invalid Content-Length") from exc
            if length < 1 or length > 65536:
                raise OAuthError("invalid_request", "Invalid request body length")
            self._json(200, self.oauth.exchange_token(self.oauth.parse_form(self.rfile.read(length))))
        except OAuthError as exc:
            self._oauth_error(exc)

    def _upstream_secret(self) -> str:
        value = self.upstream_secret_file.read_text(encoding="utf-8").strip()
        if not value:
            raise RuntimeError("upstream secret is empty")
        return value

    def _target_ready(self, parsed) -> bool:
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=8, context=ssl.create_default_context())
        try:
            conn.request("GET", parsed.path.rstrip("/") + "/health", headers={"Host": parsed.netloc, "User-Agent": "GoProxy/2.0 readiness", "Accept": "application/json"})
            resp = conn.getresponse()
            body = resp.read(8192)
            if resp.status != 200:
                return False
            try:
                return json.loads(body.decode("utf-8")).get("ok") is True
            except (UnicodeDecodeError, json.JSONDecodeError):
                return False
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
            target = str(json.loads(self.rfile.read(length)).get("target", "")).strip()
            self.state._validate_target(target)
            parsed = urlsplit(target)
            try:
                socket.getaddrinfo(parsed.hostname, parsed.port or 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            except socket.gaierror:
                self._json(503, {"ok": False, "error": "target_dns_unresolved"})
                return
            if not self._target_ready(parsed):
                self._json(503, {"ok": False, "error": "target_not_ready"})
                return
            self.state.register(target)
            self._json(200, {"ok": True, "registered": True})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})

    def _health(self) -> None:
        target, updated = self.state.snapshot()
        parsed = urlsplit(target) if target else None
        try:
            admin_ready = bool(self.admin_auth.credential_status()["username"])
        except AdminAuthError:
            admin_ready = False
        self._json(200, {"ok": True, "service": "goproxy", "oauth": True, "admin_auth": admin_ready, "issuer": self.oauth.issuer, "upstream_registered": bool(target), "upstream_host": parsed.hostname if parsed else None, "updated_at": updated or None})

    @staticmethod
    def _field_key(name: str) -> str:
        return base64.urlsafe_b64encode(name.encode("utf-8")).rstrip(b"=").decode("ascii")

    def _fetch_upstream_tools(self) -> list[dict]:
        target, _ = self.state.snapshot()
        if not target:
            raise RuntimeError("GamePC upstream is not registered")
        base = urlsplit(target)
        payload = json.dumps({"jsonrpc": "2.0", "id": "gomcp-admin-tools", "method": "tools/list", "params": {}}, separators=(",", ":")).encode("utf-8")
        conn = http.client.HTTPSConnection(base.hostname, base.port or 443, timeout=20, context=ssl.create_default_context())
        try:
            conn.request("POST", base.path.rstrip("/") + "/mcp", body=payload, headers={"Host": base.netloc, "Authorization": f"Bearer {self._upstream_secret()}", "Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity", "MCP-Protocol-Version": "2026-07-28", "User-Agent": "GoProxy-Admin/2.0"})
            resp = conn.getresponse()
            body = resp.read(16 * 1024 * 1024)
            if resp.status != 200:
                raise RuntimeError(f"GamePC tools/list returned HTTP {resp.status}")
            data = json.loads(body.decode("utf-8"))
            tools = data.get("result", {}).get("tools", []) if isinstance(data, dict) else []
            if not isinstance(tools, list):
                raise RuntimeError("GamePC tools/list did not contain a tool array")
            return [x for x in tools if isinstance(x, dict) and x.get("name")]
        finally:
            conn.close()

    def _admin_page(self, session: dict, catalog: list[dict], error: str = "", saved: bool = False) -> str:
        counts = self.tool_policy.counts(catalog)
        oauth_stats = self.oauth.stats()
        auth_status = self.admin_auth.credential_status()
        notice = '<div class="notice">Tool settings saved.</div>' if saved else ""
        error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
        tool_rows: list[str] = []
        for tool in sorted(catalog, key=lambda item: str(item.get("name", "")).casefold()):
            name = str(tool["name"])
            original = str(tool.get("description", ""))
            settings = self.tool_policy.settings_for(name)
            key = self._field_key(name)
            checked = " checked" if settings["enabled"] else ""
            description = settings["description"] or original
            klass = "tool" if settings["enabled"] else "tool disabled"
            schema = json.dumps(tool.get("inputSchema", {}), indent=2, sort_keys=True)
            tool_rows.append(f'''<div class="{klass}"><div class="row spread"><span class="toolname">{html.escape(name)}</span><label><input type="checkbox" name="enabled_{key}" value="1"{checked}>Enabled</label></div><label for="desc_{key}">Description shown to MCP clients</label><textarea id="desc_{key}" name="desc_{key}" maxlength="{self.tool_policy.MAX_DESCRIPTION}">{html.escape(description)}</textarea><details><summary>Original definition</summary><p>{html.escape(original)}</p><pre>{html.escape(schema)}</pre></details></div>''')
        tools_html = "".join(tool_rows) if tool_rows else '<p class="muted">No tools available.</p>'
        content = f'''{self._nav(session)}<section class="card"><div class="row spread"><div><h1>GoMCP Admin</h1><p>Live GamePC tool policy and OAuth status.</p></div><span class="badge">GoProxy 2.0</span></div>{notice}{error_html}<div class="grid"><div class="metric"><strong>{counts["total"]}</strong><span>Tools discovered</span></div><div class="metric"><strong>{counts["enabled"]}</strong><span>Enabled</span></div><div class="metric"><strong>{counts["disabled"]}</strong><span>Disabled</span></div><div class="metric"><strong>{oauth_stats["refresh_tokens"]}</strong><span>OAuth refresh grants</span></div></div><p class="muted">Admin sessions: {auth_status["active_sessions"]}. OAuth clients: {oauth_stats["clients"]}. Changes affect tools/list immediately and disabled tools are also blocked at tools/call.</p></section><section class="card"><h2>MCP tools</h2><form method="post" action="/goproxy/admin/tools"><input type="hidden" name="csrf" value="{html.escape(str(session.get("csrf","")), quote=True)}">{tools_html}<button type="submit">Save tool settings</button></form></section>'''
        return self._page("GoMCP Admin", content)

    def _admin_get(self) -> None:
        _, session = self._session()
        if not session:
            self._redirect("/goproxy/login")
            return
        try:
            if self.admin_auth.credential_status()["must_change_password"]:
                self._redirect("/goproxy/admin/password?required=1")
                return
            catalog = self._fetch_upstream_tools()
            query = parse_qs(urlsplit(self.path).query)
            self._html(200, self._admin_page(session, catalog, saved=query.get("saved") == ["1"]))
        except (RuntimeError, AdminAuthError) as exc:
            self._html(503, self._admin_page(session, [], error=str(exc)))

    def _admin_tools_post(self) -> None:
        _, session = self._session()
        if not session:
            self._redirect("/goproxy/login")
            return
        try:
            self._require_same_origin()
            form = self._read_form(512 * 1024)
            if not self.admin_auth.csrf_valid(session, form.get("csrf", "")):
                raise OAuthError("invalid_request", "CSRF validation failed", status=403)
            catalog = self._fetch_upstream_tools()
            enabled: dict[str, bool] = {}
            descriptions: dict[str, str] = {}
            for tool in catalog:
                name = str(tool["name"])
                key = self._field_key(name)
                enabled[name] = form.get(f"enabled_{key}") == "1"
                descriptions[name] = form.get(f"desc_{key}", "")
            self.tool_policy.update_catalog(catalog, enabled, descriptions)
            self._redirect("/goproxy/admin?saved=1")
        except OAuthError as exc:
            self._message_page("Tool settings failed", exc.description, exc.status)
        except RuntimeError as exc:
            self._message_page("Tool settings failed", str(exc), 503)

    def _blocked_mcp_response(self, body: bytes | None):
        if not body:
            return None
        try:
            request = json.loads(body.decode("utf-8"))
        except Exception:
            return None
        def tool_name(item):
            if not isinstance(item, dict) or item.get("method") != "tools/call":
                return ""
            params = item.get("params", {})
            return str(params.get("name", "")) if isinstance(params, dict) else ""
        if isinstance(request, dict):
            name = tool_name(request)
            if name and not self.tool_policy.is_enabled(name):
                return {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32004, "message": f"Tool disabled by GoMCP administrator: {name}"}}
            return None
        if isinstance(request, list):
            disabled = [name for name in (tool_name(item) for item in request) if name and not self.tool_policy.is_enabled(name)]
            if not disabled:
                return None
            response = []
            for item in request:
                if not isinstance(item, dict) or "id" not in item:
                    continue
                name = tool_name(item)
                message = f"Tool disabled by GoMCP administrator: {name}" if name and not self.tool_policy.is_enabled(name) else "Batch rejected because it included a disabled tool"
                response.append({"jsonrpc": "2.0", "id": item.get("id"), "error": {"code": -32004, "message": message}})
            return response
        return None

    @staticmethod
    def _is_tools_list(body: bytes | None) -> bool:
        if not body:
            return False
        try:
            request = json.loads(body.decode("utf-8"))
        except Exception:
            return False
        if isinstance(request, dict):
            return request.get("method") == "tools/list"
        return isinstance(request, list) and any(isinstance(item, dict) and item.get("method") == "tools/list" for item in request)

    def _apply_tool_policy_response(self, body: bytes) -> bytes:
        data = json.loads(body.decode("utf-8"))
        def apply(item):
            if isinstance(item, dict) and isinstance(item.get("result"), dict) and isinstance(item["result"].get("tools"), list):
                item["result"]["tools"] = self.tool_policy.apply_tools(item["result"]["tools"])
        if isinstance(data, list):
            for item in data:
                apply(item)
        else:
            apply(data)
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    def _proxy(self) -> None:
        target, _ = self.state.snapshot()
        if not target:
            self._json(503, {"ok": False, "error": "upstream_not_registered"})
            return
        base = urlsplit(target)
        incoming_path = self.path if self.path.startswith("/") else "/" + self.path
        upstream_path = base.path.rstrip("/") + incoming_path
        is_mcp = urlsplit(incoming_path).path == "/mcp"
        if is_mcp:
            supplied = self._bearer()
            if not (self.oauth.validate_access_token(supplied, "gomcp") if supplied else False):
                self._json(401, {"ok": False, "error": "invalid_token" if supplied else "authorization_required"}, {"WWW-Authenticate": self.oauth.bearer_challenge(invalid_token=bool(supplied))})
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
        if is_mcp:
            blocked = self._blocked_mcp_response(body)
            if blocked is not None:
                self._json(200, blocked)
                return
        transform_tools = is_mcp and self._is_tools_list(body)
        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            lower = key.lower()
            if lower in HOP_HEADERS or lower == "host" or (is_mcp and lower == "authorization"):
                continue
            if transform_tools and lower == "accept-encoding":
                continue
            headers[key] = value
        headers["Host"] = base.netloc
        headers["X-GoProxy-Forwarded-For"] = self.client_address[0]
        if transform_tools:
            headers["Accept-Encoding"] = "identity"
        if is_mcp:
            try:
                headers["Authorization"] = f"Bearer {self._upstream_secret()}"
            except RuntimeError:
                self._json(503, {"ok": False, "error": "upstream_auth_not_ready"})
                return
        conn = http.client.HTTPSConnection(base.hostname, base.port or 443, timeout=310, context=ssl.create_default_context())
        try:
            conn.request(self.command, upstream_path, body=body, headers=headers)
            resp = conn.getresponse()
            if transform_tools and resp.status == 200:
                encoded = (resp.getheader("Content-Encoding") or "identity").lower()
                raw = resp.read(32 * 1024 * 1024)
                if encoded not in ("", "identity"):
                    raise RuntimeError(f"Unexpected encoded tools/list response: {encoded}")
                try:
                    transformed = self._apply_tool_policy_response(raw)
                except Exception as exc:
                    LOG.error("Tool-policy response transform failed: %s", exc)
                    self._json(502, {"ok": False, "error": "tool_policy_transform_failed"})
                    return
                self.send_response(resp.status, resp.reason)
                for key, value in resp.getheaders():
                    lower = key.lower()
                    if lower in HOP_HEADERS or lower in {"content-length", "content-encoding"} or (is_mcp and lower == "www-authenticate"):
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(transformed)))
                self.send_header("Via", "1.1 GoProxy")
                self.end_headers()
                self.wfile.write(transformed)
                return
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
        if path == "/":
            self._redirect("/goproxy/admin")
        elif path == "/health":
            self._health()
        elif path in {"/.well-known/oauth-protected-resource/goproxy/mcp", "/.well-known/oauth-protected-resource"}:
            self._json(200, self.oauth.protected_resource_metadata())
        elif path in {"/.well-known/oauth-authorization-server/goproxy/oauth", "/oauth/.well-known/oauth-authorization-server"}:
            self._json(200, self.oauth.authorization_server_metadata())
        elif path == "/oauth/authorize":
            self._oauth_authorize_get()
        elif path == "/login":
            self._login_get()
        elif path == "/admin":
            self._admin_get()
        elif path == "/admin/password":
            self._password_get()
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
        elif path == "/login":
            self._login_post()
        elif path == "/logout":
            self._logout_post()
        elif path == "/admin/tools":
            self._admin_tools_post()
        elif path == "/admin/password":
            self._password_post()
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

    def __init__(self, address, handler, relay_state: RelayState, oauth: OAuthManager,
                 admin_auth: AdminAuth, tool_policy: ToolPolicy, upstream_secret_file: Path):
        super().__init__(address, handler)
        self.relay_state = relay_state
        self.oauth = oauth
        self.admin_auth = admin_auth
        self.tool_policy = tool_policy
        self.upstream_secret_file = upstream_secret_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default=os.getenv("GOPROXY_LISTEN", "127.0.0.1:8787"))
    parser.add_argument("--state", default=os.getenv("GOPROXY_STATE", "/home/crazytaxzi/GoProxy/state/relay.json"))
    parser.add_argument("--secret-file", default=os.getenv("GOPROXY_SECRET_FILE", "/home/crazytaxzi/GoProxy/state/register.secret"))
    parser.add_argument("--upstream-secret-file", default=os.getenv("GOPROXY_UPSTREAM_SECRET_FILE", "/home/crazytaxzi/GoProxy/state/upstream.secret"))
    parser.add_argument("--oauth-state", default=os.getenv("GOPROXY_OAUTH_STATE", "/home/crazytaxzi/GoProxy/state/oauth.json"))
    parser.add_argument("--admin-credential-file", default=os.getenv("GOPROXY_ADMIN_CREDENTIAL_FILE", "/home/crazytaxzi/GoProxy/state/admin-credential.json"))
    parser.add_argument("--admin-session-file", default=os.getenv("GOPROXY_ADMIN_SESSION_FILE", "/home/crazytaxzi/GoProxy/state/admin-sessions.json"))
    parser.add_argument("--tool-policy-file", default=os.getenv("GOPROXY_TOOL_POLICY_FILE", "/home/crazytaxzi/GoProxy/state/tool-policy.json"))
    parser.add_argument("--public-origin", default=os.getenv("GOPROXY_PUBLIC_ORIGIN", PUBLIC_ORIGIN))
    parser.add_argument("--allowed-suffix", default=os.getenv("GOPROXY_ALLOWED_SUFFIX", ".trycloudflare.com"))
    args = parser.parse_args()
    host, port_text = args.listen.rsplit(":", 1)
    state = RelayState(Path(args.state), Path(args.secret_file), args.allowed_suffix)
    oauth = OAuthManager(Path(args.oauth_state), args.public_origin)
    admin_auth = AdminAuth(Path(args.admin_credential_file), Path(args.admin_session_file))
    tool_policy = ToolPolicy(Path(args.tool_policy_file))
    admin_auth.credential_status()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = RelayHTTPServer((host, int(port_text)), Handler, state, oauth, admin_auth, tool_policy, Path(args.upstream_secret_file))
    LOG.info("GoProxy admin/OAuth relay listening on %s:%s issuer=%s", host, port_text, oauth.issuer)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
