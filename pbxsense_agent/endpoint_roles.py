"""Persistent administrator role declarations, scoped to one configured PBX."""
from dataclasses import replace
from functools import lru_cache
import json
import os
from pathlib import Path
import tempfile
import threading


class EndpointRoles:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data = json.loads(path.read_text()) if path.exists() else {}
        if not isinstance(self.data, dict) or any(
            not isinstance(rows, dict) or any(not isinstance(k, str) or v not in {'extension', 'trunk', 'ignore'} for k, v in rows.items())
            for rows in self.data.values()
        ):
            raise ValueError('Invalid endpoint role declarations')
        # Retired Ignore choices revert to connector detection on upgrade.
        self.data = {scope: {name: role for name, role in rows.items() if role != 'ignore'}
                     for scope, rows in self.data.items()}

    def choices(self, scope: str) -> dict[str, str]:
        with self.lock:
            return dict(self.data.get(scope, {}))

    def set(self, scope: str, endpoint: str, role: str):
        if not endpoint or len(endpoint) > 256 or any(ord(c) < 32 for c in endpoint):
            raise ValueError('Invalid endpoint identifier')
        if role not in {'extension', 'trunk', 'auto'}:
            raise ValueError('Invalid endpoint role')
        with self.lock:
            data = {k: dict(v) for k, v in self.data.items()}
            rows = data.setdefault(scope, {})
            if role == 'auto':
                rows.pop(endpoint, None)
            else:
                rows[endpoint] = role
            if sum(len(v) for v in data.values()) > 10000:
                raise ValueError('Endpoint role limit reached')
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix='.endpoint-roles-', dir=self.path.parent)
            try:
                with os.fdopen(fd, 'w') as stream:
                    json.dump(data, stream)
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            self.data = data

    def apply(self, snapshot, scope: str):
        choices = self.choices(scope)
        if not choices:
            return snapshot
        return replace(snapshot, endpoints=[
            replace(item, role=choices.get(item.extension, item.role))
            for item in snapshot.endpoints
        ])


@lru_cache(maxsize=8)
def role_store(path: str) -> EndpointRoles:
    return EndpointRoles(Path(path))
