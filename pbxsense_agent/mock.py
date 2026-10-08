from __future__ import annotations

from .observations import PbxChannel, PbxEndpoint, PbxQueue, PbxSnapshot
from .version import AGENT_VERSION


def mock_snapshot() -> PbxSnapshot:
    return PbxSnapshot(
        reachable=True,
        agent_version=AGENT_VERSION,
        channels=[
            PbxChannel(
                channel="PJSIP/101-00000042",
                extension="101",
                caller="Maria",
                connected="Reception",
                state="Up",
                duration="00:01:24",
            )
        ],
        endpoints=[
            PbxEndpoint(
                extension="101",
                device_state="Reachable",
                active_channels=1,
                label="Reception",
            ),
            PbxEndpoint(
                extension="120",
                device_state="Reachable",
                label="Support",
                presence="Away",
            ),
            PbxEndpoint(
                extension="130",
                device_state="Reachable",
                label="Sales",
                presence="Do Not Disturb",
            ),
            PbxEndpoint(extension="200", device_state="Unavailable", label="Warehouse"),
            PbxEndpoint(
                extension="sip-provider",
                device_state="Reachable",
                label="Main SIP trunk",
                role="trunk",
                connection_type="PJSIP",
            ),
        ],
        queues=[
            PbxQueue(
                name="support",
                waiting_callers=2,
                longest_wait_seconds=94,
                available_members=1,
                busy_members=1,
                total_members=2,
            )
        ],
    )
