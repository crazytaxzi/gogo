#!/usr/bin/env python3
"""Persistent enable/disable and description overrides for MCP tools."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


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


class ToolPolicy:
    MAX_DESCRIPTION = 2000

    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self.lock = threading.RLock()
        self._state = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("tools", {}), dict):
                return {"version": 1, "tools": raw.get("tools", {})}
        except Exception:
            pass
        return {"version": 1, "tools": {}}

    def _save_locked(self) -> None:
        self._state["updated_at"] = int(time.time())
        _atomic_json(self.state_file, self._state)

    def settings_for(self, name: str) -> dict[str, Any]:
        with self.lock:
            row = self._state.get("tools", {}).get(name, {})
            if not isinstance(row, dict):
                row = {}
            return {
                "enabled": row.get("enabled", True) is not False,
                "description": str(row.get("description", ""))[: self.MAX_DESCRIPTION],
            }

    def is_enabled(self, name: str) -> bool:
        return self.settings_for(name)["enabled"]

    def apply_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", ""))
            if not name:
                continue
            settings = self.settings_for(name)
            if not settings["enabled"]:
                continue
            item = dict(tool)
            if settings["description"]:
                item["description"] = settings["description"]
            result.append(item)
        return result

    def update_catalog(
        self,
        catalog: list[dict[str, Any]],
        enabled: dict[str, bool],
        descriptions: dict[str, str],
    ) -> None:
        known = {
            str(tool.get("name", "")): tool
            for tool in catalog
            if isinstance(tool, dict) and str(tool.get("name", ""))
        }
        with self.lock:
            rows = self._state.setdefault("tools", {})
            for name, tool in known.items():
                original_description = str(tool.get("description", ""))
                custom = descriptions.get(name, "").strip()
                row: dict[str, Any] = {}
                if not enabled.get(name, False):
                    row["enabled"] = False
                if custom and custom != original_description:
                    row["description"] = custom[: self.MAX_DESCRIPTION]
                if row:
                    rows[name] = row
                else:
                    rows.pop(name, None)
            self._save_locked()

    def counts(self, catalog: list[dict[str, Any]]) -> dict[str, int]:
        total = 0
        enabled = 0
        for tool in catalog:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            total += 1
            if self.is_enabled(str(tool["name"])):
                enabled += 1
        return {"total": total, "enabled": enabled, "disabled": total - enabled}
