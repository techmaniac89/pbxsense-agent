"""Explicit public relay route registration; handlers retain their own signatures."""
from __future__ import annotations

from typing import Callable, Mapping
from fastapi import APIRouter
from starlette.responses import HTMLResponse

# Declaration order preserves the existing OpenAPI operation ordering.
ROUTES = (
    ("GET", "/health", "health", None),
    ("GET", "/v1/internal/usage", "relay_usage", None),
    ("GET", "/admin/usage", "usage_dashboard", HTMLResponse),
    ("POST", "/admin/usage", "usage_dashboard_login", None),
    ("POST", "/v1/internal/enrollment-tickets", "create_enrollment_ticket", None),
    ("POST", "/v1/activations", "create_activation", None),
    ("POST", "/v1/activations/{activation_id}/claim", "claim_activation", None),
    ("POST", "/v1/activations/{activation_id}/status", "activation_status", None),
    ("POST", "/v1/agents/{agent_id}/devices", "register_device", None),
    ("POST", "/v1/agents/{agent_id}/devices/list", "list_devices", None),
    ("POST", "/v1/agents/{agent_id}/devices/revoke", "revoke_device", None),
    ("POST", "/v1/agents/{agent_id}/heartbeat", "heartbeat", None),
    ("POST", "/v1/agents/{agent_id}/secure/exchange", "secure_exchange", None),
    ("POST", "/v1/agents/{agent_id}/secure/snapshots", "publish_secure_snapshots", None),
    ("POST", "/v1/agents/{agent_id}/devices/{device_id}/secure-snapshot", "read_secure_snapshot", None),
    ("POST", "/v1/agents/{agent_id}/devices/{device_id}/registration", "register_own_device", None),
    ("DELETE", "/v1/agents/{agent_id}/devices/{device_id}", "revoke_own_device", None),
    ("POST", "/v1/internal/agents/{agent_id}/secure/ping", "queue_secure_ping", None),
    ("POST", "/v1/internal/sweep-agent-heartbeats", "sweep_agent_heartbeats", None),
    ("DELETE", "/v1/agents/{agent_id}/devices", "remove_device", None),
    ("POST", "/v1/agents/{agent_id}/events", "publish_event", None),
)


def create_relay_router(handlers: Mapping[str, Callable]) -> APIRouter:
    router = APIRouter()
    for method, path, name, response_class in ROUTES:
        endpoint = handlers[name]
        options = {"response_class": response_class} if response_class is not None else {}
        router.add_api_route(path, endpoint, methods=[method], **options)
    return router

