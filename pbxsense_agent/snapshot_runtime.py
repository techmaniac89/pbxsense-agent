"""Single-owner collection and generation-aware snapshot publication.

This module knows nothing about HTTP, PBX vendors, signals, or relay delivery.
Those policies are supplied as callbacks; all readers share one published state.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Generic, TypeVar


StateT = TypeVar("StateT")


@dataclass(frozen=True)
class Publication(Generic[StateT]):
    state: StateT
    published_at: float


class SnapshotRuntime(Generic[StateT]):
    def __init__(
        self,
        *,
        collect: Callable[[], StateT],
        build_payload: Callable[[StateT, int], dict],
        stale_after: float,
        stall_after: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._collect = collect
        self._build_payload = build_payload
        self._stale_after = stale_after
        self._stall_after = stall_after
        self._clock = clock
        self._state_lock = threading.Lock()
        self._collection_lock = threading.Lock()
        self._payload_lock = threading.Lock()
        self._publication: Publication[StateT] | None = None
        self._payloads: dict[int, tuple[Publication[StateT], dict]] = {}
        self._collection_started: float | None = None

    def refresh(self, *, only_if_missing: bool = False) -> StateT:
        with self._collection_lock:
            with self._state_lock:
                if only_if_missing and self._publication is not None:
                    return self._publication.state
                self._collection_started = self._clock()
            try:
                state = self._collect()
                publication = Publication(state, self._clock())
                with self._state_lock:
                    self._publication = publication
                    self._payloads.clear()
                return state
            finally:
                with self._state_lock:
                    self._collection_started = None

    def home(self, *, moment_hours: int = 24) -> dict:
        with self._state_lock:
            publication = self._publication
            cached = self._payloads.get(moment_hours)
        if cached is not None:
            return self._with_freshness(*cached)
        if publication is None:
            self.refresh(only_if_missing=True)
        # Serialize builders, which may maintain notification episode state.
        # Collection and publication can continue while a payload is rendered.
        with self._payload_lock:
            with self._state_lock:
                publication = self._publication
                cached = self._payloads.get(moment_hours)
            if cached is not None:
                return self._with_freshness(*cached)
            if publication is None:
                raise RuntimeError("No completed PBX snapshot is available")
            payload = self._build_payload(publication.state, moment_hours)
            with self._state_lock:
                if publication is self._publication:
                    self._payloads[moment_hours] = (publication, payload)
            return self._with_freshness(publication, payload)

    def _with_freshness(self, publication: Publication[StateT], payload: dict) -> dict:
        # Evaluate the returned generation, not a newer publication that might
        # have arrived while this payload was being built.
        if self._clock() - publication.published_at <= self._stale_after:
            return payload
        return {**payload, "snapshotStale": True, "connection": {
            **payload.get("connection", {}), "kind": "reconnecting", "label": "Reconnecting",
            "detail": "The last complete PBX snapshot is stale; collection is still pending.",
        }}

    def diagnostics(self) -> dict[str, object]:
        with self._state_lock:
            started = self._collection_started
        elapsed = max(0.0, self._clock() - started) if started is not None else 0.0
        return {
            "collectionInProgress": started is not None,
            "collectionElapsedSeconds": round(elapsed, 2),
            "collectionStalled": elapsed > self._stall_after,
        }
