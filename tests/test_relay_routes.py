import ast
from pathlib import Path
import unittest

from fastapi import Request
from push_relay.routes import ROUTES, create_relay_router


class RelayRoutesTests(unittest.TestCase):
    def test_route_registry_has_complete_original_method_path_contract(self):
        expected = {
            ("GET", "/health"), ("GET", "/v1/internal/usage"),
            ("GET", "/admin/usage"), ("POST", "/admin/usage"),
            ("POST", "/v1/internal/enrollment-tickets"), ("POST", "/v1/activations"),
            ("POST", "/v1/activations/{activation_id}/claim"),
            ("POST", "/v1/activations/{activation_id}/status"),
            ("POST", "/v1/agents/{agent_id}/devices"),
            ("POST", "/v1/agents/{agent_id}/devices/list"),
            ("POST", "/v1/agents/{agent_id}/devices/revoke"),
            ("POST", "/v1/agents/{agent_id}/heartbeat"),
            ("POST", "/v1/agents/{agent_id}/secure/exchange"),
            ("POST", "/v1/agents/{agent_id}/secure/snapshots"),
            ("POST", "/v1/agents/{agent_id}/devices/{device_id}/secure-snapshot"),
            ("POST", "/v1/agents/{agent_id}/devices/{device_id}/registration"),
            ("DELETE", "/v1/agents/{agent_id}/devices/{device_id}"),
            ("POST", "/v1/internal/agents/{agent_id}/secure/ping"),
            ("POST", "/v1/internal/sweep-agent-heartbeats"),
            ("DELETE", "/v1/agents/{agent_id}/devices"),
            ("POST", "/v1/agents/{agent_id}/events"),
        }
        self.assertEqual({(method, path) for method, path, _, _ in ROUTES}, expected)
        self.assertEqual(len(ROUTES), len(expected))

    def test_registration_retains_handler_objects_signatures_and_response_classes(self):
        async def endpoint(request: Request) -> dict:
            return {}
        handlers = {name: endpoint for _, _, name, _ in ROUTES}
        router = create_relay_router(handlers)
        self.assertEqual(len(router.routes), 21)
        for route, (_, path, name, response_class) in zip(router.routes, ROUTES):
            self.assertIs(route.endpoint, handlers[name])
            self.assertEqual(route.path, path)
            if response_class:
                self.assertIs(route.response_class, response_class)
            self.assertEqual(route.dependant.query_params, [])

    def test_missing_handler_fails_at_registration_not_on_first_request(self):
        with self.assertRaises(KeyError):
            create_relay_router({})

    def test_binding_map_includes_every_declared_handler(self):
        tree = ast.parse(Path("push_relay/app.py").read_text())
        call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "create_relay_router")
        bindings = call.args[0]
        self.assertEqual({key.value for key in bindings.keys},
                         {name for _, _, name, _ in ROUTES})
        self.assertEqual([key.value for key in bindings.keys],
                         [value.id for value in bindings.values])

    def test_cloud_image_copies_routes_and_authentication(self):
        source = Path("push_relay/Dockerfile").read_text()
        self.assertIn("COPY routes.py .", source)
        self.assertIn("COPY authentication.py .", source)
