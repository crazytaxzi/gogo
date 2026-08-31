#!/usr/bin/env python3
"""Single-administrator authentication and session management for GoProxy."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


class AdminAuthError(Exception):
    pass


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"), sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


class AdminAuth:
    SESSION_TTL = 30 * 24 * 3600
    PRESESSION_TTL = 10 * 60
    FAILURE_WINDOW = 15 * 60
    MAX_FAILURES = 8
    PASSWORD_MIN_CHARS = 12
    PASSWORD_MAX_CHARS = 256
    SCRYPT_MAXMEM = 256 * 1024 * 1024

    def __init__(self, credential_file: Path, session_file: Path) -> None:
        self.credential_file = credential_file
        self.session_file = session_file
        self.lock = threading.RLock()
        self._sessions = self._load_sessions()
        self._pre_sessions: dict[str, dict[str, Any]] = {}
        self._failures: dict[str, list[float]] = {}

    def _load_credential(self) -> dict[str, Any]:
        try:
            value = json.loads(self.credential_file.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise AdminAuthError("Administrator credentials are not configured") from exc
        except Exception as exc:
            raise AdminAuthError("Administrator credential file is invalid") from exc
        if not isinstance(value, dict):
            raise AdminAuthError("Administrator credential file is invalid")
        password = value.get("password")
        if (
            value.get("version") != 1
            or not isinstance(value.get("username"), str)
            or not value["username"]
            or not isinstance(password, dict)
            or password.get("scheme") != "scrypt"
        ):
            raise AdminAuthError("Administrator credential file is invalid")
        return value

    def _load_sessions(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.session_file.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return {}
            sessions = raw.get("sessions", {})
            if not isinstance(sessions, dict):
                return {}
            return {str(k): v for k, v in sessions.items() if isinstance(v, dict)}
        except FileNotFoundError:
            return {}
        except Exception:
            return {}

    def _save_sessions_locked(self) -> None:
        self._prune_sessions_locked()
        _atomic_json(self.session_file, {"version": 1, "sessions": self._sessions})

    def _prune_sessions_locked(self) -> None:
        now = time.time()
        for key, row in list(self._sessions.items()):
            if not isinstance(row, dict) or float(row.get("expires_at", 0)) <= now:
                self._sessions.pop(key, None)
        for key, row in list(self._pre_sessions.items()):
            if not isinstance(row, dict) or float(row.get("expires_at", 0)) <= now:
                self._pre_sessions.pop(key, None)

    @staticmethod
    def _hash_token(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _derive_password(cls, password: str, record: dict[str, Any]) -> bytes:
        try:
            salt = _b64d(str(record["salt"]))
            n = int(record["n"])
            r = int(record["r"])
            p = int(record["p"])
            dklen = int(record.get("dklen", 32))
        except Exception as exc:
            raise AdminAuthError("Administrator password verifier is invalid") from exc
        if n < 2**14 or r < 8 or p < 1 or dklen < 32:
            raise AdminAuthError("Administrator password verifier is too weak")
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen,
            maxmem=cls.SCRYPT_MAXMEM,
        )

    @classmethod
    def make_password_record(cls, password: str) -> dict[str, Any]:
        cls.validate_new_password(password)
        record: dict[str, Any] = {
            "scheme": "scrypt", "n": 2**16, "r": 8, "p": 2, "dklen": 32,
            "salt": _b64e(secrets.token_bytes(16)),
        }
        record["hash"] = _b64e(cls._derive_password(password, record))
        return record

    @classmethod
    def validate_new_password(cls, password: str) -> None:
        if len(password) < cls.PASSWORD_MIN_CHARS:
            raise AdminAuthError(f"New password must be at least {cls.PASSWORD_MIN_CHARS} characters")
        if len(password) > cls.PASSWORD_MAX_CHARS:
            raise AdminAuthError(f"New password must be at most {cls.PASSWORD_MAX_CHARS} characters")
        if len(password.encode("utf-8")) > 1024:
            raise AdminAuthError("New password is too large")

    def _verify_password(self, credential: dict[str, Any], password: str) -> bool:
        record = credential["password"]
        try:
            expected = _b64d(str(record["hash"]))
            actual = self._derive_password(password, record)
        except (ValueError, KeyError, AdminAuthError):
            return False
        return hmac.compare_digest(actual, expected)

    def _failure_keys(self, remote_ip: str, username: str) -> tuple[str, str]:
        return f"ip:{remote_ip}", f"account:{username.casefold()}"

    def _rate_limited_locked(self, remote_ip: str, username: str) -> bool:
        now = time.time()
        limited = False
        for key in self._failure_keys(remote_ip, username):
            recent = [x for x in self._failures.get(key, []) if x > now - self.FAILURE_WINDOW]
            self._failures[key] = recent
            limited = limited or len(recent) >= self.MAX_FAILURES
        return limited

    def authenticate(self, username: str, password: str, remote_ip: str) -> tuple[bool, str]:
        with self.lock:
            if self._rate_limited_locked(remote_ip, username):
                return False, "rate_limited"
        credential = self._load_credential()
        password_ok = self._verify_password(credential, password)
        username_ok = hmac.compare_digest(
            username.casefold().encode("utf-8"),
            str(credential["username"]).casefold().encode("utf-8"),
        )
        if username_ok and password_ok:
            with self.lock:
                for key in self._failure_keys(remote_ip, username):
                    self._failures.pop(key, None)
            return True, "ok"
        with self.lock:
            now = time.time()
            for key in self._failure_keys(remote_ip, username):
                self._failures.setdefault(key, []).append(now)
        return False, "invalid"

    def credential_status(self) -> dict[str, Any]:
        credential = self._load_credential()
        with self.lock:
            self._prune_sessions_locked()
            count = len(self._sessions)
        return {
            "username": credential["username"],
            "must_change_password": bool(credential.get("must_change_password", False)),
            "updated_at": credential.get("updated_at"),
            "active_sessions": count,
        }

    def create_pre_session(self) -> tuple[str, str]:
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            self._prune_sessions_locked()
            self._pre_sessions[self._hash_token(token)] = {
                "csrf": csrf, "expires_at": time.time() + self.PRESESSION_TTL,
            }
        return token, csrf

    def consume_pre_session(self, token: str, csrf: str) -> bool:
        if not token or not csrf:
            return False
        with self.lock:
            row = self._pre_sessions.pop(self._hash_token(token), None)
            if not isinstance(row, dict) or float(row.get("expires_at", 0)) <= time.time():
                return False
            return hmac.compare_digest(str(row.get("csrf", "")), csrf)

    def create_session(self, user_agent: str = "") -> tuple[str, dict[str, Any]]:
        credential = self._load_credential()
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = time.time()
        row = {
            "username": credential["username"], "csrf": csrf, "created_at": now,
            "expires_at": now + self.SESSION_TTL,
            "user_agent_hash": hashlib.sha256(user_agent.encode("utf-8")).hexdigest() if user_agent else "",
        }
        with self.lock:
            self._sessions[self._hash_token(token)] = row
            self._save_sessions_locked()
        return token, dict(row)

    def get_session(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        with self.lock:
            self._prune_sessions_locked()
            row = self._sessions.get(self._hash_token(token))
            return dict(row) if isinstance(row, dict) else None

    def destroy_session(self, token: str) -> None:
        if not token:
            return
        with self.lock:
            self._sessions.pop(self._hash_token(token), None)
            self._save_sessions_locked()

    def destroy_all_sessions(self) -> None:
        with self.lock:
            self._sessions.clear()
            self._save_sessions_locked()

    @staticmethod
    def csrf_valid(session: dict[str, Any] | None, supplied: str) -> bool:
        return bool(session and supplied) and hmac.compare_digest(str(session.get("csrf", "")), supplied)

    def change_password(self, username: str, current_password: str, new_password: str) -> None:
        credential = self._load_credential()
        username_ok = hmac.compare_digest(
            username.casefold().encode("utf-8"),
            str(credential["username"]).casefold().encode("utf-8"),
        )
        if not username_ok or not self._verify_password(credential, current_password):
            raise AdminAuthError("Current password is incorrect")
        self.validate_new_password(new_password)
        if self._verify_password(credential, new_password):
            raise AdminAuthError("New password must be different from the current password")
        credential["password"] = self.make_password_record(new_password)
        credential["must_change_password"] = False
        credential["updated_at"] = int(time.time())
        _atomic_json(self.credential_file, credential)
