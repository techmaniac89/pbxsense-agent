"""Configurable gross workload-cost estimates, not Cloud Billing invoices."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class RelayCostModel:
    currency: str = "USD"
    cloud_run_request_usd: float = 4.0000000000000003e-7
    cloud_run_vcpu_second_usd: float = 0.000024
    cloud_run_gib_second_usd: float = 0.0000025
    average_request_seconds: float = 0.05
    average_request_vcpu: float = 1
    average_request_memory_gib: float = 0.5
    firestore_read_usd: float = 3e-7
    firestore_write_usd: float = 9e-7
    firestore_delete_usd: float = 1e-7
    egress_gib_usd: float = 0.12

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> RelayCostModel:
        environment = os.environ if environment is None else environment
        return cls(
            currency=environment.get("PBXSENSE_RELAY_COST_CURRENCY", "USD").strip() or "USD",
            cloud_run_request_usd=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_CLOUD_RUN_REQUEST_USD", 4.0000000000000003e-7),
            cloud_run_vcpu_second_usd=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_CLOUD_RUN_VCPU_SECOND_USD", 0.000024),
            cloud_run_gib_second_usd=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_CLOUD_RUN_GIB_SECOND_USD", 0.0000025),
            average_request_seconds=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_AVERAGE_REQUEST_SECONDS", 0.05),
            average_request_vcpu=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_AVERAGE_REQUEST_VCPU", 1),
            average_request_memory_gib=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_AVERAGE_REQUEST_MEMORY_GIB", 0.5),
            firestore_read_usd=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_FIRESTORE_READ_USD", 3e-7),
            firestore_write_usd=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_FIRESTORE_WRITE_USD", 9e-7),
            firestore_delete_usd=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_FIRESTORE_DELETE_USD", 1e-7),
            egress_gib_usd=_bounded_cost_rate(environment, "PBXSENSE_RELAY_COST_EGRESS_GIB_USD", 0.12),
        )

    def estimate(self, usage: dict[str, int]) -> dict[str, float | int]:
        """Allocate gross list-price workload to one Agent; never claim invoice accuracy."""
        heartbeats = int(usage.get("heartbeats", 0))
        controls = int(usage.get("controlExchanges", 0))
        remote_reads = int(usage.get("remoteSnapshotReads", 0))
        snapshots = int(usage.get("encryptedSnapshotsPublished", 0))
        notifications = int(usage.get("notificationAttempts", 0))
        eligible = int(usage.get("notificationEligible", 0))
        invalid_tokens = int(usage.get("notificationInvalidTokens", 0))
        requests = heartbeats + controls + remote_reads + snapshots + notifications
        firestore_reads = (
            heartbeats * 2
            + controls * 3
            + remote_reads * 4
            + snapshots * 3
            + notifications * 3
            + eligible
        )
        firestore_writes = (
            heartbeats * 2
            + controls * 2
            + remote_reads * 2
            + snapshots * 2
            + notifications * 3
        )
        firestore_deletes = invalid_tokens * 2 + notifications
        published_bytes = int(usage.get("encryptedSnapshotBytes", 0))
        average_snapshot_bytes = published_bytes / snapshots if snapshots else 0
        estimated_egress_bytes = round(average_snapshot_bytes * remote_reads)
        cloud_run_cost = requests * (
            self.cloud_run_request_usd
            + self.average_request_seconds
            * (
                self.average_request_vcpu * self.cloud_run_vcpu_second_usd
                + self.average_request_memory_gib * self.cloud_run_gib_second_usd
            )
        )
        firestore_cost = (
            firestore_reads * self.firestore_read_usd
            + firestore_writes * self.firestore_write_usd
            + firestore_deletes * self.firestore_delete_usd
        )
        egress_cost = estimated_egress_bytes / (1024 ** 3) * self.egress_gib_usd
        total = cloud_run_cost + firestore_cost + egress_cost
        return {
            "requests": requests,
            "firestoreReads": firestore_reads,
            "firestoreWrites": firestore_writes,
            "firestoreDeletes": firestore_deletes,
            "estimatedEgressBytes": estimated_egress_bytes,
            "cloudRun": cloud_run_cost,
            "firestore": firestore_cost,
            "egress": egress_cost,
            "total": total,
        }


def _bounded_cost_rate(environment: Mapping[str, str], name: str, default: float) -> float:
    try:
        return max(0.0, min(1000.0, float(environment.get(name, str(default)))))
    except ValueError:
        return default

