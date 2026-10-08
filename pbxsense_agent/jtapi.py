from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .observations import PbxChannel
from .settings import AgentSettings


class JtapiBridge:
    """Own the optional Cisco JTAPI Java bridge and cache its live-call feed."""

    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings
        self._process: subprocess.Popen[str] | None = None
        self._process_lock = threading.Lock()
        self._lock = threading.Lock()
        self._calls: list[dict[str, Any]] = []
        self._updated_at = 0.0
        self._last_error = ""
        self._restart_after = 0.0
        atexit.register(self.close)

    @property
    def configured(self) -> bool:
        return bool(self._settings.cucm_jtapi_enabled and self._settings.cucm_jtapi_classpath)

    def channels(self) -> list[PbxChannel]:
        if not self.configured:
            return []
        self._ensure_running()
        with self._lock:
            if time.monotonic() - self._updated_at > self._settings.cucm_jtapi_stale_seconds:
                return []
            calls = list(self._calls)
        return [_channel_from_call(call) for call in calls if call.get("id")]

    def diagnostics(self) -> dict[str, object]:
        if not self.configured:
            return {
                "jtapiConfigured": False,
                "jtapiReachable": False,
                "liveCallsAvailable": False,
                "jtapiMessage": "JTAPI is optional and is not configured.",
            }
        self._ensure_running()
        with self._lock:
            age = time.monotonic() - self._updated_at if self._updated_at else None
            process_running = self._process is not None and self._process.poll() is None
            reachable = process_running and age is not None and age <= self._settings.cucm_jtapi_stale_seconds
            result: dict[str, object] = {
                "jtapiConfigured": True,
                "jtapiCredentialsConfigured": bool(
                    (self._settings.cucm_jtapi_username or self._settings.cucm_username)
                    and (self._settings.cucm_jtapi_password or self._settings.cucm_password)
                ),
                "jtapiProcessRunning": process_running,
                "jtapiReachable": reachable,
                "liveCallsAvailable": reachable,
                "jtapiSnapshotAgeSeconds": round(age, 1) if age is not None else None,
                "jtapiActiveCalls": len(self._calls) if reachable else 0,
            }
            if self._last_error:
                result["jtapiError"] = self._last_error
            result["jtapiMessage"] = (
                "JTAPI is streaming live calls."
                if reachable
                else "JTAPI is configured but no fresh live-call snapshot is available."
            )
            return result

    def close(self) -> None:
        process = self._process
        self._process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()

    def _ensure_running(self) -> None:
        with self._process_lock:
            self._ensure_running_locked()

    def _ensure_running_locked(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            return
        now = time.monotonic()
        if now < self._restart_after:
            return
        self._restart_after = now + self._settings.cucm_jtapi_restart_seconds
        java = shutil.which(self._settings.cucm_jtapi_java) or self._settings.cucm_jtapi_java
        bridge_classes = Path(__file__).resolve().parent.parent / "jtapi_bridge" / "classes"
        classpath = self._settings.cucm_jtapi_classpath
        if not (bridge_classes / "PBXSenseJtapiBridge.class").is_file():
            self._last_error = "Compiled JTAPI bridge is missing"
            return
        classpath_root = Path(classpath.rstrip("*"))
        if not classpath_root.exists():
            self._last_error = "Configured Cisco JTAPI classpath is not readable"
            return
        env = os.environ.copy()
        env.update(
            {
                "PBXSENSE_JTAPI_HOST": self._settings.cucm_host,
                "PBXSENSE_JTAPI_USERNAME": self._settings.cucm_jtapi_username or self._settings.cucm_username,
                "PBXSENSE_JTAPI_PASSWORD": self._settings.cucm_jtapi_password or self._settings.cucm_password,
                "PBXSENSE_JTAPI_POLL_MS": str(int(self._settings.cucm_jtapi_poll_seconds * 1000)),
            }
        )
        try:
            self._process = subprocess.Popen(
                [
                    java,
                    "-cp",
                    os.pathsep.join((classpath, str(bridge_classes))),
                    "PBXSenseJtapiBridge",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
        except OSError as exc:
            self._last_error = f"Could not start Java JTAPI bridge: {exc}"
            return
        threading.Thread(target=self._read_stdout, args=(self._process,), daemon=True).start()
        threading.Thread(target=self._read_stderr, args=(self._process,), daemon=True).start()

    def _read_stdout(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            try:
                payload = json.loads(line)
                calls = payload.get("calls")
                if not isinstance(calls, list):
                    continue
                with self._lock:
                    self._calls = [item for item in calls if isinstance(item, dict)]
                    self._updated_at = time.monotonic()
                    self._last_error = ""
            except (TypeError, ValueError):
                continue

    def _read_stderr(self, process: subprocess.Popen[str]) -> None:
        assert process.stderr is not None
        for line in process.stderr:
            message = line.strip()
            if message:
                with self._lock:
                    self._last_error = message[:500]


def _channel_from_call(call: dict[str, Any]) -> PbxChannel:
    call_id = str(call.get("id", "")).strip()
    caller = str(call.get("caller", "")).strip()
    destination = str(call.get("destination", "")).strip()
    extension = str(call.get("extension", "")).strip() or caller
    return PbxChannel(
        channel=f"JTAPI/{call_id}",
        extension=extension,
        caller=caller,
        connected=destination,
        state=str(call.get("state", "Up")),
        endpoint=extension,
        caller_number=caller,
        connected_number=destination,
        duration=str(call.get("duration", "")),
        unique_id=call_id,
        linked_id=call_id,
    )
