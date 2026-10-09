"""Bounded, private daily evidence; recent history is not a complete-day ledger."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from contextlib import closing
from datetime import datetime, timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3

from .history import interpreted_call_kind
from .observations import PbxSnapshot

RETENTION_DAYS = 370
MAX_EVENT_KEYS = 100_000
DAY_START_GRACE_SECONDS = 60


class DailySummaryTracker:
    def __init__(self, path: str, *, history_seconds: float = 30,
                 queue_gap_seconds: float = 10, identity: str = "") -> None:
        self.path = Path(path)
        self.history_gap = max(120, history_seconds * 3)
        self.queue_gap = queue_gap_seconds
        self.identity = hashlib.sha256(identity.encode()).hexdigest()
        self.days: dict[str, dict] = {}
        self.last_queue = 0.0
        self.last_history = 0.0
        self.last_key = ""
        self.saved_at = 0.0
        self.persisted_breach_day = ""
        self.storage_ready = False
        self._load()

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=2)
        db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, day TEXT NOT NULL, count INTEGER NOT NULL)")
        os.chmod(self.path, 0o600)
        return db

    def _load(self):
        if not self.path.exists():
            return
        try:
            if self.path.stat().st_size > 32 * 1024 * 1024:
                return
            with closing(sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True)) as db:
                row = db.execute("SELECT body FROM state WHERE id=1").fetchone()
            raw = json.loads(row[0]) if row else {}
            if not isinstance(raw, dict):
                return
            if raw.get("identity") != self.identity:
                return
            days = raw.get("days", {})
            if not isinstance(days, dict) or len(days) > RETENTION_DAYS + 1:
                return
            for key, day in days.items():
                if datetime.fromisoformat(key).date().isoformat() != key or not isinstance(day, dict):
                    return
                if any(type(day.get(field)) is not int or day[field] < 0 for field in
                       ("calls", "answered", "missed", "voicemail", "maxWait")):
                    return
                if any(type(day.get(field)) is not bool for field in
                       ("callsComplete", "voicemailComplete", "queuesComplete", "queuesEmpty")):
                    return
                if not isinstance(day.get("firstAnswered"), str) or len(day["firstAnswered"]) > 8:
                    return
                if not isinstance(day.get("queueNames"), list) or len(day["queueNames"]) > 1000 or any(
                        not isinstance(name, str) or len(name) > 1024 for name in day["queueNames"]):
                    return
            last_queue = float(raw.get("last_queue", 0))
            last_history = float(raw.get("last_history", 0))
            if not all(math.isfinite(value) and 0 <= value <= 253402214400 for value in (last_queue, last_history)):
                return
            self.days = days
            self.last_queue = last_queue
            self.last_history = last_history
            self.last_key = str(raw.get("last_key", ""))
        except (OSError, sqlite3.Error, ValueError, TypeError):
            self.days = {}

    def _day(self, day: str, now: datetime) -> dict:
        if day not in self.days:
            start = now.hour * 3600 + now.minute * 60 + now.second
            candidate = day == now.date().isoformat() and start <= DAY_START_GRACE_SECONDS
            self.days[day] = {"calls": 0, "answered": 0, "missed": 0, "voicemail": 0,
                "firstAnswered": "", "callsComplete": candidate, "voicemailComplete": candidate,
                "queuesComplete": candidate, "queueNames": [], "maxWait": 0, "queuesEmpty": False}
        return self.days[day]

    def _invalidate(self, previous: float, now: datetime, fields: tuple[str, ...]):
        first = datetime.fromtimestamp(previous, now.tzinfo).date() if previous else now.date()
        first = min(first, now.date())
        for key, day in self.days.items():
            if first.isoformat() <= key <= now.date().isoformat():
                for field in fields:
                    day[field] = False

    def observe(self, snapshot: PbxSnapshot, now: datetime) -> dict:
        stamp = now.timestamp()
        day = self._day(now.date().isoformat(), now)
        flags = (day["callsComplete"], day["queuesComplete"], day["voicemailComplete"])
        queue_ready = snapshot.reachable and snapshot.sources.get("queues", {}).get("state", "ready") == "ready"
        if not queue_ready or (self.last_queue and not 0 <= stamp - self.last_queue <= self.queue_gap):
            self._invalidate(self.last_queue, now, ("queuesComplete",))
        if self.last_queue and datetime.fromtimestamp(self.last_queue, now.tzinfo).date() != now.date() and snapshot.channels:
            # Calls crossing midnight can still produce CDRs for yesterday.
            self._invalidate(self.last_queue, now, ("callsComplete",))
        names = sorted({queue.name for queue in snapshot.queues})
        if self.last_queue and datetime.fromtimestamp(self.last_queue, now.tzinfo).date() == now.date() and names != day["queueNames"]:
            day["queuesComplete"] = False
        day["queueNames"] = sorted(set(day["queueNames"]) | set(names))
        day["maxWait"] = max(day["maxWait"], max((queue.longest_wait_seconds for queue in snapshot.queues), default=0))
        day["queuesEmpty"] = queue_ready and bool(names) and all(queue.waiting_callers == 0 for queue in snapshot.queues)
        self.last_queue = stamp

        source = snapshot.sources.get("cdr", {})
        age = source.get("lastSuccessAgeSeconds")
        history_ready = snapshot.reachable and source.get("state", "ready") == "ready" and (age is None or age <= self.history_gap)
        read_at = stamp - float(age or 0)
        fresh = read_at - self.last_history >= 1
        if not history_ready or (self.last_history and not 0 <= read_at - self.last_history <= self.history_gap):
            self._invalidate(self.last_history, now, ("callsComplete", "voicemailComplete"))
        if snapshot.sources.get("voicemail", {}).get("state", "ready") != "ready":
            day["voicemailComplete"] = False
        try:
            if fresh and history_ready:
                previous = deepcopy(self.days), self.last_history, self.last_key
                try:
                    self._history(snapshot, now, read_at)
                except (OSError, sqlite3.Error, ValueError, TypeError):
                    self.days, self.last_history, self.last_key = previous
                    raise
            changed = flags != (day["callsComplete"], day["queuesComplete"], day["voicemailComplete"])
            if changed or stamp - self.saved_at >= 60 or (day["maxWait"] > 60 and self.persisted_breach_day != now.date().isoformat()):
                self._save(now)
                if day["maxWait"] > 60:
                    self.persisted_breach_day = now.date().isoformat()
        except (OSError, sqlite3.Error, ValueError, TypeError):
            self.storage_ready = False
            day = self._day(now.date().isoformat(), now)
            day["callsComplete"] = day["queuesComplete"] = day["voicemailComplete"] = False
        # Copy facts into the publication; later observations must not mutate it.
        return {"available": self.storage_ready, "lastHistoryAt": self.last_history,
                "days": deepcopy(self.days)}

    def _history(self, snapshot: PbxSnapshot, now: datetime, read_at: float):
        batches = Counter()
        facts = {}
        oldest = (now.date() - timedelta(days=2)).isoformat()
        for call in snapshot.recent_calls:
            if call.started_at is None:
                self._day(now.date().isoformat(), now)["callsComplete"] = False
                continue
            at = call.started_at.astimezone(now.tzinfo) if call.started_at.tzinfo else call.started_at
            date = at.date().isoformat()
            if not oldest <= date <= now.date().isoformat():
                continue
            kind = interpreted_call_kind(call)
            if kind not in {"answered", "missed", "ivr_reached"}:
                continue
            key = hashlib.sha256(json.dumps([self.identity, str(call.started_at), call.source, call.destination,
                call.channel, call.destination_channel, call.disposition, call.duration_seconds,
                call.last_app, call.last_data], separators=(",", ":")).encode()).hexdigest()
            batches[key] += 1
            facts[key] = (date, kind, at.strftime("%H:%M:%S"))
        if (self.last_key and self.last_key not in batches) or (not self.last_key and len(snapshot.recent_calls) >= 1000):
            self._invalidate(self.last_history, now, ("callsComplete",))
        with closing(self._connect()) as db, db:
            db.execute("DELETE FROM seen WHERE day < ?", (oldest,))
            known = {}
            keys = list(batches)
            for offset in range(0, len(keys), 800):
                chunk = keys[offset:offset + 800]
                known.update(db.execute(f"SELECT key,count FROM seen WHERE key IN ({','.join('?' for _ in chunk)})", chunk))
            if db.execute("SELECT count(*) FROM seen").fetchone()[0] + len(batches.keys() - known.keys()) + len(snapshot.voicemails) > MAX_EVENT_KEYS:
                self._invalidate(self.last_history, now, ("callsComplete", "voicemailComplete"))
                self.last_history = read_at
                self._save(now, db)
                return
            for key, count in batches.items():
                delta = max(0, count - known.get(key, 0))
                if not delta:
                    continue
                date, kind, at = facts[key]
                day = self._day(date, now)
                day["calls"] += delta
                if kind == "answered":
                    day["answered"] += delta
                    day["firstAnswered"] = min(day["firstAnswered"] or at, at)
                elif kind == "missed":
                    day["missed"] += delta
                db.execute("INSERT OR REPLACE INTO seen VALUES (?,?,?)", (key, date, count))
            if snapshot.sources.get("voicemail", {}).get("state", "ready") == "ready":
                for message in snapshot.voicemails:
                    if message.created_at is None:
                        self._day(now.date().isoformat(), now)["voicemailComplete"] = False
                        continue
                    at = message.created_at.astimezone(now.tzinfo) if message.created_at.tzinfo else message.created_at
                    date = at.date().isoformat()
                    if not oldest <= date <= now.date().isoformat():
                        continue
                    key = "v" + hashlib.sha256(f"{self.identity}|{message.mailbox}|{message.caller}|{message.created_at}".encode()).hexdigest()
                    if db.execute("SELECT 1 FROM seen WHERE key=?", (key,)).fetchone() is None:
                        self._day(date, now)["voicemail"] += 1
                        db.execute("INSERT INTO seen VALUES (?,?,1)", (key, date))
            if len(snapshot.voicemails) >= 100:
                self._day(now.date().isoformat(), now)["voicemailComplete"] = False
            self.last_key = max(facts, key=lambda key: (facts[key][0], facts[key][2])) if facts else ""
            self.last_history = read_at
            self._save(now, db)

    def _save(self, now: datetime, db=None):
        cutoff = (now.date() - timedelta(days=RETENTION_DAYS)).isoformat()
        self.days = {key: day for key, day in self.days.items() if key >= cutoff}
        body = json.dumps({"identity": self.identity, "days": self.days,
            "last_history": self.last_history, "last_queue": self.last_queue, "last_key": self.last_key})
        if db is None:
            with closing(self._connect()) as connection, connection:
                self._save(now, connection)
            return
        db.execute("INSERT OR REPLACE INTO state VALUES (1,?)", (body,))
        self.saved_at = now.timestamp()
        self.storage_ready = True
