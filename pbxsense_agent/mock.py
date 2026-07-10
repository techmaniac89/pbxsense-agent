from __future__ import annotations

from .pulse import AmiChannel, AmiEndpoint, AmiSnapshot
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
            ),
        ],
    )
