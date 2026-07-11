from __future__ import annotations

from typing import Protocol

from .ami import AmiClient
from .freeswitch import FreeSwitchClient
from .grandstream import GrandstreamUcmClient
from .mock import mock_snapshot
from .pulse import AmiSnapshot
from .settings import AgentSettings
from .yeastar import YeastarClient


class PBXConnector(Protocol):
    name: str
    diagnostics_label: str

    def snapshot(self) -> AmiSnapshot:
        ...

    def diagnostics(self) -> dict:
        ...


class MockConnector:
    name = "mock"
    diagnostics_label = "Mock"

    def snapshot(self) -> AmiSnapshot:
        return mock_snapshot()

    def diagnostics(self) -> dict:
        return {
            "pbxType": "mock",
            "ok": True,
            "message": "Mock connector is running.",
        }


def connector_for_settings(settings: AgentSettings) -> PBXConnector:
    if settings.pbx_type == "mock" or settings.mode == "mock":
        return MockConnector()
    if settings.pbx_type == "freeswitch":
        return FreeSwitchClient(settings)
    if settings.pbx_type == "yeastar":
        return YeastarClient(settings)
    if settings.pbx_type == "grandstream":
        return GrandstreamUcmClient(settings)
    return AmiClient(settings)
