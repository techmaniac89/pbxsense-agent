"""Named domain state published by the snapshot runtime."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .observations import PbxEndpoint, PbxSnapshot


@dataclass(frozen=True, kw_only=True)
class CollectedHomeState:
    """One collected generation; field bindings are immutable, contents are not.

    This is internal state, not an API payload. The runtime owns publication;
    callers must not mutate its collections after publication.
    """

    snapshot: PbxSnapshot
    observed_at: datetime
    moment_events: list[dict]
    endpoint_unavailability_signals: set[str]
    endpoint_notification_ids: dict[str, str]
    endpoint_unavailability_evidence: dict[str, PbxEndpoint]
    endpoint_signal_lifecycle: dict[str, dict[str, str]]
    trunk_unavailability_signals: set[str]
    show_aggregate_tip: bool
    endpoint_last_active: dict[str, datetime]
    daily_summaries: dict = field(default_factory=dict)
