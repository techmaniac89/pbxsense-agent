"""Coordinate signal observations within one serialized snapshot generation."""
from __future__ import annotations

from datetime import datetime

from .collected_state import CollectedHomeState
from .observations import PbxSnapshot
from .presence_history import EndpointLastActiveTracker
from .pulse import ActivityTracker, EndpointAvailabilitySignalTracker, EndpointAggregateTipTracker
from .daily_summary import DailySummaryTracker


class SignalCollector:
    """Tracker configuration/lifecycle belongs to the composition root.

    Calls are serialized by SnapshotRuntime. Notification episode IDs applied
    during payload construction remain outside this observation boundary.
    """

    def __init__(
        self, *, activity: ActivityTracker,
        endpoints: EndpointAvailabilitySignalTracker,
        trunks: EndpointAvailabilitySignalTracker,
        aggregate_tip: EndpointAggregateTipTracker,
        last_active: EndpointLastActiveTracker,
        daily: DailySummaryTracker | None = None,
    ) -> None:
        self._activity = activity
        self._endpoints = endpoints
        self._trunks = trunks
        self._aggregate_tip = aggregate_tip
        self._last_active = last_active
        self._daily = daily

    def collect(self, snapshot: PbxSnapshot, observed_at: datetime) -> CollectedHomeState:
        moment_events = self._activity.observe(snapshot, observed_at)
        endpoint_signals = self._endpoints.observe(snapshot, observed_at)
        notification_ids = self._endpoints.notification_ids()
        evidence = self._endpoints.signal_endpoints()
        lifecycle = self._endpoints.signal_lifecycle()
        trunk_signals = self._trunks.observe(snapshot, observed_at)
        show_tip = self._aggregate_tip.observe(snapshot, observed_at)
        last_active = self._last_active.observe(snapshot, observed_at)
        daily = self._daily.observe(snapshot, observed_at) if self._daily else {}
        return CollectedHomeState(
            snapshot=snapshot, observed_at=observed_at, moment_events=moment_events,
            endpoint_unavailability_signals=endpoint_signals,
            endpoint_notification_ids=notification_ids,
            endpoint_unavailability_evidence=evidence,
            endpoint_signal_lifecycle=lifecycle,
            trunk_unavailability_signals=trunk_signals,
            show_aggregate_tip=show_tip, endpoint_last_active=last_active,
            daily_summaries=daily,
        )
