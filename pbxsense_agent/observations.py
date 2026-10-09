"""Vendor-neutral connector observations; not the public JSON wire format.

Frozen bindings preserve existing semantics. Snapshot lists remain owned by the
publisher; freezing a dataclass does not make its contained collections immutable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .history import CdrCall, SecurityEvent, VoicemailMessage


@dataclass(frozen=True)
class PbxChannel:
    channel: str
    extension: str
    caller: str
    connected: str
    state: str
    endpoint: str = ""
    caller_number: str = ""
    connected_number: str = ""
    duration: str = ""
    unique_id: str = ""
    linked_id: str = ""


@dataclass(frozen=True)
class PbxEndpoint:
    extension: str
    device_state: str
    active_channels: int = 0
    label: str = ""
    role: str = "extension"
    connection_type: str = ""
    number: str = ""
    # A PBX-provided presence state, such as DND or Away. This is kept apart
    # from device_state: a phone can be registered while its owner is away.
    presence: str = ""
    ip_address: str = ""
    health_status: str = ""
    health_confidence: str = ""
    health_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class PbxQueue:
    name: str
    waiting_callers: int = 0
    longest_wait_seconds: int = 0
    available_members: int = 0
    busy_members: int = 0
    paused_members: int = 0
    total_members: int = 0


@dataclass(frozen=True)
class PbxSnapshot:
    reachable: bool
    agent_version: str
    channels: list[PbxChannel] = field(default_factory=list)
    endpoints: list[PbxEndpoint] = field(default_factory=list)
    queues: list[PbxQueue] = field(default_factory=list)
    recent_calls: list[CdrCall] = field(default_factory=list)
    voicemails: list[VoicemailMessage] = field(default_factory=list)
    security_events: list[SecurityEvent] = field(default_factory=list)
    error: str | None = None
    sources: dict[str, dict] = field(default_factory=dict)

