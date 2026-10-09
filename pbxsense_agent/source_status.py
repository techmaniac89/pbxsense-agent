"""Source-local availability: an empty successful read is not a failed read."""
from __future__ import annotations

import time
from threading import Lock


class SourceStatus:
    def __init__(self) -> None:
        self._values: dict[str, tuple[str, float | None]] = {}
        self._lock = Lock()

    def record(self, name: str, state: str = "ready") -> None:
        with self._lock:
            previous = self._values.get(name, (state, None))[1]
            self._values[name] = (state, time.monotonic() if state == "ready" else previous)

    def export(self) -> dict[str, dict]:
        now = time.monotonic()
        with self._lock:
            return {name: {"state": state, "lastSuccessAgeSeconds":
                    round(max(0, now - success), 1) if success is not None else None}
                    for name, (state, success) in self._values.items()}


def rejection_state(error: Exception) -> str:
    # Classify internally; never publish raw vendor messages or credentials.
    message = str(error).lower()
    if any(word in message for word in ("permission", "privilege", "access denied")):
        return "permission_denied"
    if any(word in message for word in ("unknown command", "invalid command", "invalid action", "unsupported", "not supported", "module not loaded")):
        return "unsupported"
    return "temporarily_unavailable"
