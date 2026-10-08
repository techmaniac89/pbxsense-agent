import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

from pbxsense_agent.snapshot_runtime import SnapshotRuntime


class SnapshotRuntimeTest(unittest.TestCase):
    def runtime(self, collect, build=None, clock=None):
        return SnapshotRuntime(
            collect=collect,
            build_payload=build or (lambda state, hours: {"state": state, "hours": hours,
                                                          "snapshotStale": False,
                                                          "connection": {"kind": "local"}}),
            stale_after=10, stall_after=60, clock=clock or (lambda: 0.0),
        )

    def test_cache_variants_are_invalidated_by_publication(self):
        collect = Mock(side_effect=["first", "second"])
        runtime = self.runtime(collect)
        first = runtime.home()
        self.assertIs(first, runtime.home())
        variant = runtime.home(moment_hours=48)
        self.assertEqual(variant["hours"], 48)
        self.assertIsNot(first, variant)
        runtime.refresh()
        self.assertEqual(runtime.home()["state"], "second")
        self.assertIsNot(first, runtime.home())
        self.assertIsNot(variant, runtime.home(moment_hours=48))

    def test_failed_collection_preserves_previous_publication_and_resets_status(self):
        clock = [0.0]
        collect = Mock(side_effect=["first", OSError("PBX offline")])
        runtime = self.runtime(collect, clock=lambda: clock[0])
        cached = runtime.home()
        with self.assertRaises(OSError):
            runtime.refresh()
        self.assertIs(runtime.home(), cached)
        self.assertFalse(runtime.diagnostics()["collectionInProgress"])
        clock[0] = 11
        stale = runtime.home()
        self.assertTrue(stale["snapshotStale"])
        self.assertEqual(stale["connection"]["kind"], "reconnecting")
        self.assertFalse(cached["snapshotStale"])
        self.assertEqual(cached["connection"]["kind"], "local")

    def test_concurrent_first_readers_collect_and_build_only_once(self):
        entered, release = threading.Event(), threading.Event()
        def collect():
            entered.set()
            release.wait(2)
            return "first"
        collector = Mock(side_effect=collect)
        builder = Mock(return_value={"state": "first"})
        runtime = self.runtime(collector, builder)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(runtime.home) for _ in range(8)]
            try:
                self.assertTrue(entered.wait(1))
            finally:
                release.set()
            results = [future.result(timeout=2) for future in futures]
        collector.assert_called_once()
        builder.assert_called_once()
        self.assertTrue(all(result is results[0] for result in results))

    def test_late_old_generation_build_does_not_poison_new_cache(self):
        clock = [0.0]
        entered, release = threading.Event(), threading.Event()
        def build(state, hours):
            if state == "old":
                entered.set()
                release.wait(2)
            return {"state": state, "snapshotStale": False}
        runtime = self.runtime(Mock(side_effect=["old", "new"]), build, lambda: clock[0])
        runtime.refresh()
        with ThreadPoolExecutor(max_workers=1) as pool:
            old_build = pool.submit(runtime.home)
            try:
                self.assertTrue(entered.wait(1))
                clock[0] = 20
                runtime.refresh()
            finally:
                release.set()
            old_payload = old_build.result(timeout=2)
        # Freshness belongs to the returned generation, not the newest state.
        self.assertTrue(old_payload["snapshotStale"])
        self.assertEqual(old_payload["state"], "old")
        current = runtime.home()
        self.assertEqual(current["state"], "new")
        self.assertFalse(current["snapshotStale"])
        self.assertIs(current, runtime.home())

    def test_failed_builder_retries_without_recollecting(self):
        collector = Mock(return_value="state")
        builder = Mock(side_effect=[ValueError("bad payload"), {"ok": True}])
        runtime = self.runtime(collector, builder)
        with self.assertRaises(ValueError):
            runtime.home()
        self.assertEqual(runtime.home(), {"ok": True})
        collector.assert_called_once()
        self.assertEqual(builder.call_count, 2)

    def test_stalled_collection_is_visible_but_not_restarted(self):
        clock = [0.0]
        entered, release = threading.Event(), threading.Event()
        def collect():
            entered.set()
            release.wait(2)
            return "state"
        collector = Mock(side_effect=collect)
        runtime = self.runtime(collector, clock=lambda: clock[0])
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(runtime.refresh)
            try:
                self.assertTrue(entered.wait(1))
                clock[0] = 61
                self.assertTrue(runtime.diagnostics()["collectionStalled"])
                self.assertEqual(runtime.diagnostics()["collectionElapsedSeconds"], 61)
                collector.assert_called_once()
            finally:
                release.set()
            future.result(timeout=2)
        self.assertFalse(runtime.diagnostics()["collectionInProgress"])
        self.assertFalse(runtime.diagnostics()["collectionStalled"])
