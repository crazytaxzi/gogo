#!/usr/bin/env python3
"""Small single-owner OAuth 2.1 authorization server for GoMCP.

The public OAuth authority is anchored to the stable GoProxy URL. Dynamic clients are
restricted to HTTPS redirect URIs on chatgpt.com. Authorization uses a high-entropy
owner key whose SHA-256 verifier is synchronized from GAMEPC; the key itself never
leaves GAMEPC except when the owner submits it over HTTPS on the authorization form.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit


_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_HEX_256_RE = re.compile(r"^[0-9a-f]{64}$")


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


class OAuthManager:
    ACCESS_TTL = 3600
    REFRESH_TTL = 30 * 24 * 3600
    CODE_TTL = 180
    REQUEST_TTL = 600
    MAX_CLIENTS = 200
    MAX_FAILED_LOGINS = 8
    FAILED_LOGIN_WINDOW = 600

    def __init__(
        self,
        state_file: Path,
        owner_hash_file: Path,
        public_origin: str = "https://8.235.7.248",
    ) -> None:
        self.state_file = state_file
        self.owner_hash_file = owner_hash_file
        self.public_origin = public_origin.rstrip("/")
        self.resource = f"{self.public_origin}/goproxy/mcp"
        self.issuer = f"{self.public_origin}/goproxy/oauth"
        self.protected_resource_metadata_url = (
            f"{self.public_origin}/.well-known/oauth-protected-resource/goproxy/mcp"
        )
        self.authorization_server_metadata_url = (
            f"{self.public_origin}/.well-known/oauth-authorization-server/goproxy/oauth"
        )
        self.authorization_endpoint = f"{self.issuer}/authorize"
        self.token_endpoint = f"{self.issuer}/token"
        self.registration_endpoint = f"{self.issuer}/register"
        self.lock = threading.RLock()
        self.failed_logins: dict[str, list[float]] = {}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state = self._load()

    @staticmethod
    def _blank_state() -> dict[str, Any]:
        return {
            "clients": {},
            "authorization_requests": {},
            "codes": {},
            "access_tokens": {},
            "refresh_tokens": {},
        }

    def _load(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("OAuth state root must be an object")
        except FileNotFoundError:
            return self._blank_state()
        except Exception:
            try:
                damaged = self.state_file.with_suffix(
                    self.state_file.suffix + f".damaged.{int(time.time())}"
                )
                os.replace(self.state_file, damaged)
            except Exception:
                pass
            return self._blank_state()

        blank = self._blank_state()
        for key in blank:
            value = raw.get(key, {})
            blank[key] = value if isinstance(value, dict) else {}
        return blank

    def _save_locked(self) -> None:
        self._prune_locked()
        fd, temp_name = tempfile.mkstemp(
            prefix="oauth.", suffix=".json", dir=self.state_file.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh, separators=(",", ":"), sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_name, self.state_file)
            try:
                os.chmod(self.state_file, 0o600)
            except OSError:
                pass
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def _prune_locked(self) -> None:
        now = time.time()
        for bucket in ("authorization_requests", "codes", "access_tokens", "refresh_tokens"):
            rows = self._state[bucket]
            for key, row in list(rows.items()):
                if not isinstance(row, dict) or float(row.get("expires_at", 0)) <= now:
                    rows.pop(key, None)

        clients = self._state["clients"]
        if len(clients) > self.MAX_CLIENTS:
            ordered = sorted(
                clients.items(),
                key=lambda item: float(item[1].get("last_used_at", item[1].get("created_at", 0))),
            )
            for client_id, _ in ordered[: len(clients) - self.MAX_CLIENTS]:
                clients.pop(client_id, None)

    @staticmethod
    def _hash_secret(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _token(prefix: str = "") -> str:
        return prefix + secrets.token_urlsafe(36)

    @staticmethod
    def _normalize_scope(scope: str | None) -> list[str]:
        allowed = {"gomcp", "offline_access"}
        parts = [item for item in (scope or "").split() if item]
        if not parts:
            return ["gomcp", "offline_access"]
        unknown = set(parts) - allowed
        if unknown:
            raise OAuthError("invalid_scope", f"Unsupported scope: {sorted(unknown)[0]}")
        if "gomcp" not in parts:
            parts.insert(0, "gomcp")
        if "offline_access" not in parts:
            parts.append("offline_access")
        return list(dict.fromkeys(parts))

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "resource_name": "GoMCP GamePC",
            "authorization_servers": [self.issuer],
            "scopes_supported": ["gomcp", "offline_access"],
            "bearer_methods_supported": ["header"],
        }

    def authorization_server_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "registration_endpoint": self.registration_endpoint,
            "scopes_supported": ["gomcp", "offline_access"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
        }

    @staticmethod
    def _validate_redirect_uri(uri: str) -> str:
        parsed = urlsplit(uri)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() != "chatgpt.com"
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.query
            or not parsed.path.startswith("/connector/oauth/")
        ):
            raise OAuthError(
                "invalid_redirect_uri",
                "GoMCP dynamic clients must use an HTTPS chatgpt.com /connector/oauth/ callback",
            )
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

    def register_client(self, metadata: dict[str, Any]) -> dict[str, Any]:
        redirects = metadata.get("redirect_uris")
        if not isinstance(redirects, list) or not redirects:
            raise OAuthError("invalid_client_metadata", "redirect_uris is required")
        if len(redirects) > 8:
            raise OAuthError("invalid_client_metadata", "Too many redirect URIs")
        normalized_redirects = [self._validate_redirect_uri(str(uri)) for uri in redirects]

        auth_method = str(metadata.get("token_endpoint_auth_method", "none"))
        if auth_method != "none":
            raise OAuthError(
                "invalid_client_metadata",
                "Only token_endpoint_auth_method=none is supported",
            )

        grant_types = metadata.get("grant_types", ["authorization_code", "refresh_token"])
        if not isinstance(grant_types, list) or not set(grant_types).issubset(
            {"authorization_code", "refresh_token"}
        ):
            raise OAuthError("invalid_client_metadata", "Unsupported grant_types")
        if "authorization_code" not in grant_types:
            grant_types.append("authorization_code")
        if "refresh_token" not in grant_types:
            grant_types.append("refresh_token")

        response_types = metadata.get("response_types", ["code"])
        if not isinstance(response_types, list) or set(response_types) != {"code"}:
            raise OAuthError("invalid_client_metadata", "Only response_type=code is supported")

        application_type = str(metadata.get("application_type", "web"))
        if application_type not in {"web", "native"}:
            raise OAuthError("invalid_client_metadata", "Unsupported application_type")

        now = time.time()
        client_id = self._token("gomcp_")
        record = {
            "client_id": client_id,
            "client_name": str(metadata.get("client_name", "ChatGPT GoMCP"))[:200],
            "redirect_uris": normalized_redirects,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "application_type": application_type,
            "created_at": now,
            "last_used_at": now,
        }
        with self.lock:
            self._state["clients"][client_id] = record
            self._save_locked()

        return {
            "client_id": client_id,
            "client_id_issued_at": int(now),
            "client_name": record["client_name"],
            "redirect_uris": normalized_redirects,
            "token_endpoint_auth_method": "none",
            "grant_types": record["grant_types"],
            "response_types": record["response_types"],
            "application_type": application_type,
        }

    def _get_client_locked(self, client_id: str) -> dict[str, Any]:
        client = self._state["clients"].get(client_id)
        if not isinstance(client, dict):
            raise OAuthError("invalid_client", "Unknown client_id", status=401)
        return client

    def begin_authorization(self, query: dict[str, list[str]]) -> str:
        def one(name: str, required: bool = True) -> str:
            values = query.get(name, [])
            if not values:
                if required:
                    raise OAuthError("invalid_request", f"Missing {name}")
                return ""
            if len(values) != 1:
                raise OAuthError("invalid_request", f"Duplicate {name}")
            return values[0]

        client_id = one("client_id")
        redirect_uri = self._validate_redirect_uri(one("redirect_uri"))
        response_type = one("response_type")
        state = one("state", required=False)
        code_challenge = one("code_challenge")
        code_challenge_method = one("code_challenge_method")
        scope = one("scope", required=False)
        resource_values = query.get("resource", [])

        if response_type != "code":
            raise OAuthError("unsupported_response_type", "Only response_type=code is supported")
        if code_challenge_method != "S256" or not code_challenge:
            raise OAuthError("invalid_request", "PKCE S256 is required")
        if resource_values and any(resource != self.resource for resource in resource_values):
            raise OAuthError("invalid_target", "Requested resource does not match GoMCP")
        scopes = self._normalize_scope(scope)

        with self.lock:
            client = self._get_client_locked(client_id)
            if redirect_uri not in client.get("redirect_uris", []):
                raise OAuthError("invalid_request", "redirect_uri is not registered")
            request_id = self._token("req_")
            self._state["authorization_requests"][request_id] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": scopes,
                "resource": self.resource,
                "created_at": time.time(),
                "expires_at": time.time() + self.REQUEST_TTL,
            }
            client["last_used_at"] = time.time()
            self._save_locked()
        return request_id

    def _owner_hash(self) -> str:
        try:
            value = self.owner_hash_file.read_text(encoding="ascii").strip().lower()
        except FileNotFoundError as exc:
            raise OAuthError(
                "temporarily_unavailable",
                "GoMCP owner authorization has not been synchronized yet",
                status=503,
            ) from exc
        if not _HEX_256_RE.fullmatch(value):
            raise OAuthError(
                "server_error", "GoMCP owner authorization verifier is invalid", status=500
            )
        return value

    def login_allowed(self, remote_ip: str) -> bool:
        now = time.time()
        with self.lock:
            recent = [
                stamp
                for stamp in self.failed_logins.get(remote_ip, [])
                if stamp > now - self.FAILED_LOGIN_WINDOW
            ]
            self.failed_logins[remote_ip] = recent
            return len(recent) < self.MAX_FAILED_LOGINS

    def note_failed_login(self, remote_ip: str) -> None:
        with self.lock:
            self.failed_logins.setdefault(remote_ip, []).append(time.time())

    def authorization_form(self, request_id: str, error: str = "") -> str:
        with self.lock:
            request = self._state["authorization_requests"].get(request_id)
            if not isinstance(request, dict) or float(request.get("expires_at", 0)) <= time.time():
                raise OAuthError("invalid_request", "Authorization request expired")
            client = self._get_client_locked(str(request["client_id"]))
            client_name = str(client.get("client_name", "ChatGPT"))
        error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize GoMCP</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#151515;color:#eee;margin:0;display:grid;place-items:center;min-height:100vh}}
main{{width:min(520px,calc(100% - 32px));background:#232323;border:1px solid #444;border-radius:16px;padding:28px;box-sizing:border-box}}
h1{{margin:0 0 8px;font-size:24px}}p{{color:#c9c9c9;line-height:1.5}}label{{display:block;margin:20px 0 8px;font-weight:600}}
input{{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #666;background:#151515;color:#fff;font-size:16px}}
button{{margin-top:18px;width:100%;padding:12px;border:0;border-radius:999px;background:#fff;color:#111;font-weight:700;font-size:16px;cursor:pointer}}
.error{{background:#4a211c;border:1px solid #a44;color:#ffd5cc;padding:10px;border-radius:8px;margin:14px 0}}
.small{{font-size:13px;color:#aaa}}
</style></head><body><main>
<h1>Authorize GoMCP</h1>
<p><strong>{html.escape(client_name)}</strong> is requesting access to the GamePC MCP server. This grants access to the tools exposed by GoMCP.</p>
{error_html}
<form method="post" action="/goproxy/oauth/authorize" autocomplete="off">
<input type="hidden" name="request_id" value="{html.escape(request_id, quote=True)}">
<label for="access_key">GoMCP owner key</label>
<input id="access_key" name="access_key" type="password" required autofocus autocomplete="current-password">
<button type="submit">Authorize ChatGPT</button>
</form>
<p class="small">The owner key is stored only on GAMEPC at C:\\actions-runner\\GoMCP\\state\\mcp.token.</p>
</main></body></html>"""

    def finish_authorization(self, request_id: str, access_key: str, remote_ip: str) -> str:
        if not self.login_allowed(remote_ip):
            raise OAuthError("access_denied", "Too many failed owner-key attempts", status=429)
        owner_hash = self._owner_hash()
        supplied_hash = self._hash_secret(access_key)
        if not hmac.compare_digest(owner_hash, supplied_hash):
            self.note_failed_login(remote_ip)
            raise OAuthError("access_denied", "Owner key is incorrect", status=401)

        with self.lock:
            request = self._state["authorization_requests"].pop(request_id, None)
            if not isinstance(request, dict) or float(request.get("expires_at", 0)) <= time.time():
                raise OAuthError("invalid_request", "Authorization request expired")
            code = self._token("code_")
            self._state["codes"][self._hash_secret(code)] = {
                **request,
                "expires_at": time.time() + self.CODE_TTL,
            }
            self._save_locked()

        params = {"code": code, "iss": self.issuer}
        if request.get("state"):
            params["state"] = str(request["state"])
        separator = "&" if "?" in str(request["redirect_uri"]) else "?"
        return str(request["redirect_uri"]) + separator + urlencode(params)

    @staticmethod
    def _pkce_matches(verifier: str, expected: str) -> bool:
        if not _PKCE_VERIFIER_RE.fullmatch(verifier):
            return False
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        actual = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return hmac.compare_digest(actual, expected)

    def _issue_tokens_locked(self, client_id: str, scope: list[str], resource: str) -> dict[str, Any]:
        now = time.time()
        access_token = self._token("at_")
        refresh_token = self._token("rt_")
        self._state["access_tokens"][self._hash_secret(access_token)] = {
            "client_id": client_id,
            "scope": scope,
            "resource": resource,
            "issued_at": now,
            "expires_at": now + self.ACCESS_TTL,
        }
        self._state["refresh_tokens"][self._hash_secret(refresh_token)] = {
            "client_id": client_id,
            "scope": scope,
            "resource": resource,
            "issued_at": now,
            "expires_at": now + self.REFRESH_TTL,
        }
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.ACCESS_TTL,
            "refresh_token": refresh_token,
            "scope": " ".join(scope),
        }

    def exchange_token(self, form: dict[str, list[str]]) -> dict[str, Any]:
        def one(name: str, required: bool = True) -> str:
            values = form.get(name, [])
            if not values:
                if required:
                    raise OAuthError("invalid_request", f"Missing {name}")
                return ""
            if len(values) != 1:
                raise OAuthError("invalid_request", f"Duplicate {name}")
            return values[0]

        grant_type = one("grant_type")
        client_id = one("client_id")

        if grant_type == "authorization_code":
            code = one("code")
            redirect_uri = self._validate_redirect_uri(one("redirect_uri"))
            verifier = one("code_verifier")
            resource = one("resource", required=False)
            if resource and resource != self.resource:
                raise OAuthError("invalid_target", "Requested resource does not match GoMCP")

            with self.lock:
                self._get_client_locked(client_id)
                code_hash = self._hash_secret(code)
                row = self._state["codes"].pop(code_hash, None)
                if not isinstance(row, dict) or float(row.get("expires_at", 0)) <= time.time():
                    self._save_locked()
                    raise OAuthError("invalid_grant", "Authorization code is invalid or expired")
                if row.get("client_id") != client_id or row.get("redirect_uri") != redirect_uri:
                    self._save_locked()
                    raise OAuthError("invalid_grant", "Authorization code binding mismatch")
                if not self._pkce_matches(verifier, str(row.get("code_challenge", ""))):
                    self._save_locked()
                    raise OAuthError("invalid_grant", "PKCE verification failed")
                result = self._issue_tokens_locked(
                    client_id,
                    list(row.get("scope", ["gomcp", "offline_access"])),
                    str(row.get("resource", self.resource)),
                )
                self._state["clients"][client_id]["last_used_at"] = time.time()
                self._save_locked()
                return result

        if grant_type == "refresh_token":
            refresh_token = one("refresh_token")
            requested_scope = one("scope", required=False)
            resource = one("resource", required=False)
            if resource and resource != self.resource:
                raise OAuthError("invalid_target", "Requested resource does not match GoMCP")

            with self.lock:
                self._get_client_locked(client_id)
                refresh_hash = self._hash_secret(refresh_token)
                row = self._state["refresh_tokens"].pop(refresh_hash, None)
                if not isinstance(row, dict) or float(row.get("expires_at", 0)) <= time.time():
                    self._save_locked()
                    raise OAuthError("invalid_grant", "Refresh token is invalid or expired")
                if row.get("client_id") != client_id:
                    self._save_locked()
                    raise OAuthError("invalid_grant", "Refresh token client mismatch")
                original_scope = list(row.get("scope", ["gomcp", "offline_access"]))
                if requested_scope:
                    requested = self._normalize_scope(requested_scope)
                    if not set(requested).issubset(set(original_scope)):
                        self._save_locked()
                        raise OAuthError("invalid_scope", "Refresh scope exceeds original grant")
                    scope = requested
                else:
                    scope = original_scope
                result = self._issue_tokens_locked(client_id, scope, str(row.get("resource", self.resource)))
                self._state["clients"][client_id]["last_used_at"] = time.time()
                self._save_locked()
                return result

        raise OAuthError("unsupported_grant_type", "Unsupported grant_type")

    def validate_access_token(self, token: str, required_scope: str = "gomcp") -> bool:
        if not token:
            return False
        token_hash = self._hash_secret(token)
        with self.lock:
            self._prune_locked()
            row = self._state["access_tokens"].get(token_hash)
            if not isinstance(row, dict):
                return False
            if float(row.get("expires_at", 0)) <= time.time():
                self._state["access_tokens"].pop(token_hash, None)
                self._save_locked()
                return False
            if row.get("resource") != self.resource:
                return False
            scope = row.get("scope", [])
            return isinstance(scope, list) and required_scope in scope

    def bearer_challenge(self, invalid_token: bool = False) -> str:
        challenge = (
            f'Bearer resource_metadata="{self.protected_resource_metadata_url}", '
            'scope="gomcp"'
        )
        if invalid_token:
            challenge += ', error="invalid_token"'
        return challenge

    @staticmethod
    def parse_form(body: bytes) -> dict[str, list[str]]:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OAuthError("invalid_request", "Form body must be UTF-8") from exc
        return parse_qs(text, keep_blank_values=True, strict_parsing=False)
