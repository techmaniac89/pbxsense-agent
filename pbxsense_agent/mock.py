from __future__ import annotations

from .pulse import AmiChannel, AmiEndpoint, AmiQueue, AmiSnapshot
from .version import AGENT_VERSION


def mock_snapshot() -> AmiSnapshot:
    return AmiSnapshot(
        reachable=True,
        agent_version=AGENT_VERSION,
        channels=[
            AmiChannel(
                channel="PJSIP/101-00000042",
                extension="101",
                caller="Maria",
                connected="Reception",
                state="Up",
                duration="00:01:24",
            )
        ],
        endpoints=[
            AmiEndpoint(
                extension="101",
                device_state="Reachable",
                active_channels=1,
                label="Reception",
            ),
            AmiEndpoint(
                extension="120",
                device_state="Reachable",
                label="Support",
                presence="Away",
            ),
            AmiEndpoint(
                extension="130",
                device_state="Reachable",
                label="Sales",
                presence="Do Not Disturb",
            ),
            AmiEndpoint(extension="200", device_state="Unavailable", label="Warehouse"),
            AmiEndpoint(
                extension="sip-provider",
                device_state="Reachable",
                label="Main SIP trunk",
                role="trunk",
                connection_type="PJSIP",
            ),
        ],
        queues=[
            AmiQueue(
                name="support",
                waiting_callers=2,
                longest_wait_seconds=94,
                available_members=1,
                busy_members=1,
                total_members=2,
            )
        ],
    )
