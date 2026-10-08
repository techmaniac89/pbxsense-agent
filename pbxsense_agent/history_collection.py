"""File-history coordination owned by the serialized snapshot collector."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
import time
from typing import Callable

from .cucm import enrich_cucm_trunks_with_history
from .history import (
    CdrCall, SecurityEvent, VoicemailMessage, read_recent_cdr_calls,
    read_recent_cucm_calls, read_recent_security_events, read_recent_voicemails,
)
from .observations import PbxSnapshot
from .settings import AgentSettings


@dataclass(frozen=True)
class HistoryRecords:
    calls: list[CdrCall] = field(default_factory=list)
    voicemails: list[VoicemailMessage] = field(default_factory=list)
    security_events: list[SecurityEvent] = field(default_factory=list)


def history_paths(settings: AgentSettings) -> tuple[str, str]:
    if settings.pbx_type == "grandstream":
        return settings.grandstream_cdr_csv_path, settings.grandstream_voicemail_path
    return settings.cdr_csv_path, settings.voicemail_path


def security_log_path(settings: AgentSettings) -> str:
    if settings.pbx_type == "grandstream":
        return settings.grandstream_security_log_path
    return settings.asterisk_security_log_path


def file_signature(path: str) -> tuple[str, int, int]:
    """Return cheap change evidence for an append-oriented history file."""
    if not path:
        return ("", 0, 0)
    try:
        stat = Path(path).stat()
        return (path, stat.st_size, stat.st_mtime_ns)
    except OSError:
        return (path, 0, 0)


def voicemail_signature(path: str) -> tuple[tuple[str, int, int], ...]:
    """Fingerprint voicemail metadata without reopening message contents."""
    if not path:
        return ()
    try:
        entries = []
        for item in Path(path).glob("**/INBOX/msg*.txt"):
            stat = item.stat()
            entries.append((str(item), stat.st_size, stat.st_mtime_ns))
        return tuple(sorted(entries))
    except OSError:
        return ()


class HistoryCollector:
    """Merge local history; connector-owned API/JSON history passes through.

    SnapshotRuntime serializes calls. This service must not be used concurrently
    or mutate collections after they have been published in a snapshot.
    """

    def __init__(
        self, *, poll_interval: float,
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = datetime.now,
        read_calls: Callable[..., list[CdrCall]] = read_recent_cdr_calls,
        read_cucm: Callable[..., list[CdrCall]] = read_recent_cucm_calls,
        read_voicemails: Callable[..., list[VoicemailMessage]] = read_recent_voicemails,
        read_security: Callable[..., list[SecurityEvent]] = read_recent_security_events,
    ) -> None:
        self._poll_interval = poll_interval
        self._monotonic = monotonic
        self._now = now
        self._read_calls = read_calls
        self._read_cucm = read_cucm
        self._read_voicemails = read_voicemails
        self._read_security = read_security
        self._records = HistoryRecords()
        self._refreshed_at: float | None = None
        self._cdr_signature = None
        self._voicemail_signature = None
        self._security_signature = None

    def enrich(self, snapshot: PbxSnapshot, settings: AgentSettings) -> PbxSnapshot:
        if settings.pbx_type not in {"asterisk", "grandstream", "cucm"}:
            return snapshot
        now_monotonic = self._monotonic()
        if self._refreshed_at is None or now_monotonic - self._refreshed_at >= self._poll_interval:
            self._refresh(settings)
            self._refreshed_at = now_monotonic
        records = self._records
        endpoints = snapshot.endpoints
        if settings.pbx_type == "cucm":
            endpoints = enrich_cucm_trunks_with_history(endpoints, records.calls)
        return replace(snapshot, endpoints=endpoints, recent_calls=records.calls,
                       voicemails=records.voicemails, security_events=records.security_events)

    def _refresh(self, settings: AgentSettings) -> None:
        if settings.pbx_type == "cucm":
            self._records = HistoryRecords(calls=self._read_cucm(
                settings.cucm_cdr_path, settings.cucm_cmr_path, limit=1000,
            ))
            return
        cdr_path, voicemail_path = history_paths(settings)
        cdr_signature = file_signature(cdr_path)
        voicemail_fingerprint = voicemail_signature(voicemail_path)
        security_path = security_log_path(settings)
        security_signature = file_signature(security_path)
        calls = self._records.calls
        voicemails = self._records.voicemails
        security_events = self._records.security_events
        if self._cdr_signature != cdr_signature:
            calls = self._read_calls(cdr_path, limit=1000)
        if self._voicemail_signature != voicemail_fingerprint:
            voicemails = self._read_voicemails(voicemail_path)
        if self._security_signature != security_signature:
            security_events = self._read_security(security_path)
        else:
            cutoff = self._now() - timedelta(minutes=15)
            security_events = [event for event in security_events
                               if event.occurred_at is not None and event.occurred_at >= cutoff]
        # Commit records and fingerprints only after every reader succeeded.
        self._records = HistoryRecords(calls, voicemails, security_events)
        self._cdr_signature = cdr_signature
        self._voicemail_signature = voicemail_fingerprint
        self._security_signature = security_signature
