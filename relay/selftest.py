#!/usr/bin/env python3
"""Offline relay security/behavior smoke tests used before deployment."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from admin_auth import AdminAuth
from oauth import OAuthManager
from tool_policy import ToolPolicy


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="gomcp-relay-selftest-"))
    try:
        credential = root / "admin.json"
        shutil.copy2(Path(__file__).with_name("admin-bootstrap.json"), credential)
        auth = AdminAuth(credential, root / "sessions.json")
        status = auth.credential_status()
        assert status["username"] == "admin"
        assert status["must_change_password"] is True

        test_password = "A secure temporary passphrase 123!"
        record = {
            "version": 1,
            "username": "admin",
            "password": AdminAuth.make_password_record(test_password),
            "must_change_password": True,
            "updated_at": 1,
        }
        credential.write_text(json.dumps(record), encoding="utf-8")
        ok, reason = auth.authenticate("admin", test_password, "127.0.0.1")
        assert ok and reason == "ok"
        ok, reason = auth.authenticate("admin", "definitely wrong", "127.0.0.2")
        assert not ok and reason == "invalid"

        pre, csrf = auth.create_pre_session()
        assert auth.consume_pre_session(pre, csrf)
        assert not auth.consume_pre_session(pre, csrf)

        session_token, session = auth.create_session("selftest")
        assert auth.get_session(session_token)
        assert auth.csrf_valid(session, session["csrf"])

        auth.change_password("admin", test_password, "A different secure passphrase 456!")
        assert auth.credential_status()["must_change_password"] is False

        policy = ToolPolicy(root / "policy.json")
        catalog = [
            {"name": "alpha", "description": "Alpha", "inputSchema": {}},
            {"name": "beta", "description": "Beta", "inputSchema": {}},
        ]
        policy.update_catalog(
            catalog,
            {"alpha": True, "beta": False},
            {"alpha": "Edited Alpha", "beta": "Beta"},
        )
        filtered = policy.apply_tools(catalog)
        assert [tool["name"] for tool in filtered] == ["alpha"]
        assert filtered[0]["description"] == "Edited Alpha"
        assert not policy.is_enabled("beta")

        oauth_state = root / "oauth.json"
        oauth = OAuthManager(oauth_state, "https://gomcp-8-235-7-248.nip.io")
        client = oauth.register_client(
            {
                "client_name": "Selftest",
                "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "application_type": "web",
            }
        )
        query = parse_qs(
            "response_type=code"
            f"&client_id={client['client_id']}"
            "&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector_platform_oauth_redirect"
            "&code_challenge=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            "&code_challenge_method=S256"
            "&state=test"
            "&scope=gomcp+offline_access"
            "&resource=https%3A%2F%2Fgomcp-8-235-7-248.nip.io%2Fgoproxy%2Fmcp"
        )
        request_id = oauth.begin_authorization(query)
        assert oauth.get_authorization_request(request_id)["client_name"] == "Selftest"

        oauth_reloaded = OAuthManager(oauth_state, "https://gomcp-8-235-7-248.nip.io")
        assert oauth_reloaded.get_authorization_request(request_id)["request_id"] == request_id
        redirect = oauth_reloaded.approve_authorization(request_id)
        parsed = urlsplit(redirect)
        returned = parse_qs(parsed.query)
        assert returned["state"] == ["test"]
        assert returned["iss"] == ["https://gomcp-8-235-7-248.nip.io/goproxy/oauth"]
        assert returned["code"][0].startswith("code_")

        print("relay_selftest=success auth=scrypt sessions=secure_state csrf=present tool_policy=success oauth_persistence=success")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
