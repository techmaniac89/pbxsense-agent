from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from threading import Lock

from .observations import PbxSnapshot
from .pulse import _endpoint_unavailable


class EndpointLastActiveTracker:
    """Remember the final healthy observation before an endpoint went offline."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = Lock()
        self._last_active = self._load()
        self._was_available: dict[str, bool] = {}

    def observe(self, snapshot: PbxSnapshot, now: datetime) -> dict[str, datetime]:
        if not snapshot.reachable:
            return self.snapshot()
        changed = False
        with self._lock:
            for endpoint in snapshot.endpoints:
                if endpoint.role == "trunk" or endpoint.health_status == "unknown":
                    continue
                extension = endpoint.extension
                available = not _endpoint_unavailable(endpoint)
                if available:
                    self._last_active[extension] = now
                elif self._was_available.get(extension) is True:
                    changed = True
                self._was_available[extension] = available
            if changed:
                self._save_locked()
            return dict(self._last_active)

    def snapshot(self) -> dict[str, datetime]:
        with self._lock:
            return dict(self._last_active)

    def _load(self) -> dict[str, datetime]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return {}
            recovered = {}
            for extension, value in raw.items():
                if not extension or not isinstance(value, str):
                    continue
                try:
                    recovered[extension] = datetime.fromisoformat(value)
                except ValueError:
                    continue
            return recovered
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return {}

    def _save_locked(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_suffix(self._path.suffix + ".tmp")
            temporary.write_text(
                json.dumps({key: value.isoformat() for key, value in self._last_active.items()}),
                encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            temporary.replace(self._path)
        except OSError:
            return
