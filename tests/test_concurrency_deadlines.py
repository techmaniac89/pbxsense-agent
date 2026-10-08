import ast
import asyncio
import threading
import inspect
import time
import unittest
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch

from pbxsense_agent import main
from pbxsense_agent.ami import AmiClient, AmiError
from pbxsense_agent.freeswitch import FreeSwitchClient, FreeSwitchError
from pbxsense_agent.connectors import MockConnector
from pbxsense_agent.settings import AgentSettings
from pbxsense_agent.snapshot_runtime import SnapshotRuntime
from push_relay.backend_worker import backend_worker
from starlette.requests import Request


class DripSocket:
    def __init__(self, clock, packet=b"x"):
        self.clock, self.packet = clock, packet
        self.reads = 0

    def settimeout(self, seconds):
        self.timeout = seconds

    def recv(self, size, flags=0):
        self.clock[0] += 0.4
        self.reads += 1
        return self.packet[:size]

    def sendall(self, data):
        pass


class ConcurrencyDeadlineTest(unittest.TestCase):
    def test_ami_trickled_frame_has_absolute_deadline(self):
        clock = [0.0]
        sock = DripSocket(clock)
        client = AmiClient(replace(AgentSettings.from_env(), timeout_seconds=1))
        with patch("pbxsense_agent.socket_deadline.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(AmiError):
                client._read_packet(sock, phase="test")
        self.assertLessEqual(sock.reads, 4)

    def test_esl_trickled_header_has_absolute_deadline(self):
        clock = [0.0]
        sock = DripSocket(clock)
        client = FreeSwitchClient(replace(AgentSettings.from_env(), timeout_seconds=1))
        with patch("pbxsense_agent.socket_deadline.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(FreeSwitchError):
                client._read_reply(sock, phase="test")
        self.assertLessEqual(sock.reads, 4)

    def test_ami_many_complete_packets_cannot_extend_action(self):
        clock = [0.0]
        sock = DripSocket(clock, b"Event: Item\r\n\r\n")
        client = AmiClient(replace(AgentSettings.from_env(), timeout_seconds=1))
        with patch("pbxsense_agent.socket_deadline.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(AmiError):
                client._collect_action_events(sock, action="test", complete_event="Never")
        self.assertLessEqual(sock.reads, 4)

    def test_cached_home_is_available_during_collection(self):
        entered, release = threading.Event(), threading.Event()
        worker = None
        clock = [0.0]
        runtime = SnapshotRuntime(
            collect=lambda: main._collect_home_state(),
            build_payload=lambda state, hours: main._home_payload_from_state(state, moment_hours=hours),
            stale_after=10, stall_after=60, clock=lambda: clock[0],
        )
        try:
            with patch.object(main, "connector", MockConnector()), patch.object(main, "_snapshot_runtime", runtime):
                state = main._refresh_home_state()
                cached = main._home_payload()
                def collect():
                    entered.set()
                    release.wait(2)
                    return state
                with patch.object(main, "_collect_home_state", side_effect=collect):
                    worker = threading.Thread(target=main._refresh_home_state)
                    worker.start()
                    self.assertTrue(entered.wait(1))
                    self.assertIs(main._home_payload(), cached)
                    # A second reader can inspect freshness without PBX I/O.
                    clock[0] = 100
                    stale = main._home_payload()
                    self.assertTrue(stale["snapshotStale"])
                    self.assertEqual(stale["connection"]["kind"], "reconnecting")
                    self.assertFalse(cached["snapshotStale"])
                    self.assertTrue(main._runtime_diagnostics()["snapshot"]["collectionInProgress"])
                    release.set()
                    worker.join(2)
        finally:
            release.set()
            if worker:
                worker.join(2)

    def test_backend_work_does_not_block_event_loop(self):
        entered, release = threading.Event(), threading.Event()
        @backend_worker
        async def endpoint(value: int) -> int:
            entered.set()
            release.wait(2)
            return value
        async def scenario():
            task = asyncio.create_task(endpoint(7))
            try:
                for _ in range(100):
                    if entered.is_set():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(entered.is_set())
                self.assertFalse(task.done())
                release.set()
                self.assertEqual(await task, 7)
            finally:
                release.set()
                await task
        asyncio.run(scenario())

    def test_all_async_routes_use_backend_workers_not_middleware(self):
        from push_relay.routes import ROUTES
        registered_names = {name for _, _, name, _ in ROUTES}
        tree = ast.parse(Path("push_relay/app.py").read_text(encoding="utf-8"))
        checked = set()
        for node in tree.body:
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            if node.name in registered_names:
                self.assertTrue(any(isinstance(d, ast.Name) and d.id == "backend_worker" for d in node.decorator_list), node.name)
                checked.add(node.name)
        self.assertEqual(checked, registered_names - {"health"})

    def test_request_stream_is_consumed_on_original_loop(self):
        reader_threads = []
        async def receive():
            reader_threads.append(threading.get_ident())
            return {"type": "http.request", "body": b"body", "more_body": False}
        @backend_worker
        async def endpoint(request: Request) -> bytes:
            self.assertNotEqual(threading.get_ident(), original_thread)
            return await request.body()
        original_thread = threading.get_ident()
        request = Request({"type": "http", "method": "POST", "path": "/", "headers": []}, receive)
        self.assertEqual(asyncio.run(endpoint(request)), b"body")
        self.assertEqual(reader_threads, [original_thread])
        self.assertIs(inspect.signature(endpoint).parameters["request"].annotation, Request)

    def test_backend_pool_never_exceeds_16_active_jobs(self):
        active, maximum = [0], [0]
        lock = threading.Lock()
        release = threading.Event()
        @backend_worker
        async def endpoint() -> None:
            with lock:
                active[0] += 1
                maximum[0] = max(maximum[0], active[0])
            release.wait(2)
            with lock:
                active[0] -= 1
        async def scenario():
            tasks = [asyncio.create_task(endpoint()) for _ in range(20)]
            try:
                for _ in range(100):
                    with lock:
                        count = active[0]
                    if count == 16:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(count, 16)
                self.assertLessEqual(maximum[0], 16)
            finally:
                release.set()
                await asyncio.gather(*tasks)
        asyncio.run(scenario())
