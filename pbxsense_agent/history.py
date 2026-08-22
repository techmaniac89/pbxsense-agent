from __future__ import annotations

import csv
import fnmatch
import heapq
import io
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import re

MAX_CUCM_ENTRIES_SCANNED = 50_000
MAX_CUCM_CSV_FILE_BYTES = 8 * 1024 * 1024
MAX_CUCM_ROWS = 20_000

MISSED_CDR_DISPOSITIONS = {"NO ANSWER", "BUSY", "FAILED", "CONGESTION"}
IVR_REACHED_KIND = "ivr_reached"


@dataclass(frozen=True)
class CdrCall:
    source: str
    destination: str
    disposition: str
    started_at: datetime | None
    duration_seconds: int
    context: str = ""
    channel: str = ""
    destination_channel: str = ""
    last_app: str = ""
    last_data: str = ""
    recording_id: str = ""
    packet_loss_percent: float | None = None
    jitter_ms: float | None = None
    latency_ms: float | None = None


@dataclass(frozen=True)
class VoicemailMessage:
    mailbox: str
    caller: str
    created_at: datetime | None


@dataclass(frozen=True)
class SecurityEvent:
    kind: str
    service: str
    occurred_at: datetime | None


_SECURITY_EVENT_PATTERN = re.compile(r'SecurityEvent="?([^",\s]+)')
_SECURITY_SERVICE_PATTERN = re.compile(r'Service="?([^",\s]+)')
_SECURITY_LOG_TIME_PATTERN = re.compile(r"^\[([^\]]+)\]")
_SUPPORTED_SECURITY_EVENTS = {
    "InvalidAccountID",
    "InvalidPassword",
    "ChallengeResponseFailed",
    "FailedACL",
    "RequestBadFormat",
}


def read_recent_cdr_calls(path: str, *, limit: int = 30) -> list[CdrCall]:
    cdr_path = Path(path)
    if not _is_file(cdr_path):
        return []

    try:
        rows = _recent_cdr_rows(cdr_path, limit=limit)
    except OSError:
        return []

    calls: list[CdrCall] = []
    for row in rows[-limit * 3 :]:
        if len(row) < 14:
            continue
        calls.append(
            CdrCall(
                source=row[1].strip(),
                destination=row[2].strip(),
                disposition=row[14].strip().upper() if len(row) > 14 else "",
                started_at=_parse_datetime(row[9].strip()),
                duration_seconds=_parse_int(row[12].strip()),
                context=row[3].strip() if len(row) > 3 else "",
                channel=row[5].strip() if len(row) > 5 else "",
                destination_channel=row[6].strip() if len(row) > 6 else "",
                last_app=row[7].strip() if len(row) > 7 else "",
                last_data=row[8].strip() if len(row) > 8 else "",
                recording_id=_recording_id_from_row(row),
            )
        )

    calls.sort(key=lambda call: call.started_at or datetime.min, reverse=True)
    return calls[:limit]


def read_recent_cucm_calls(
    cdr_path: str, cmr_path: str, *, limit: int = 1000
) -> list[CdrCall]:
    """Read completed CUCM CDRs and attach matching CMR quality evidence."""
    quality = _cucm_quality_by_call(cmr_path)
    calls: list[CdrCall] = []
    for row in _cucm_csv_rows(cdr_path, file_limit=40):
        started_at = _parse_timestamp(row.get("dateTimeOrigination", ""))
        duration = _parse_int(row.get("duration", ""))
        call_key = _cucm_call_key(row)
        metrics = quality.get(call_key, {})
        destination = (
            row.get("finalCalledPartyNumber", "").strip()
            or row.get("originalCalledPartyNumber", "").strip()
        )
        source = row.get("callingPartyNumber", "").strip()
        if not source and not destination:
            continue
        calls.append(CdrCall(
            source=source,
            destination=destination,
            disposition="ANSWERED" if duration > 0 else "NO ANSWER",
            started_at=started_at,
            duration_seconds=duration,
            context=row.get("origDeviceName", "").strip(),
            channel=row.get("origDeviceName", "").strip(),
            destination_channel=row.get("destDeviceName", "").strip(),
            packet_loss_percent=metrics.get("packet_loss_percent"),
            jitter_ms=metrics.get("jitter_ms"),
            latency_ms=metrics.get("latency_ms"),
        ))
    calls.sort(key=lambda call: call.started_at or datetime.min, reverse=True)
    return calls[:limit]


def cucm_history_diagnostics(cdr_path: str, cmr_path: str) -> dict[str, object]:
    cdr_root, cmr_root = Path(cdr_path), Path(cmr_path)
    return {
        "cdrPath": str(cdr_root),
        "cdrPathExists": _is_dir(cdr_root),
        "cdrPathReadable": _is_readable_dir(cdr_root),
        "cdrFiles": _count_csv_files(cdr_root),
        "recentCallsReadable": len(read_recent_cucm_calls(cdr_path, cmr_path, limit=5)),
        "cmrPath": str(cmr_root),
        "cmrPathExists": _is_dir(cmr_root),
        "cmrPathReadable": _is_readable_dir(cmr_root),
        "cmrFiles": _count_csv_files(cmr_root),
        "qualityRecordsReadable": len(_cucm_quality_by_call(cmr_path)),
    }


def _cucm_csv_rows(path: str, *, file_limit: int) -> list[dict[str, str]]:
    root = Path(path)
    if not _is_dir(root):
        return []
    files = _recent_tree_files(root, "*.csv", file_limit)
    rows: list[dict[str, str]] = []
    for item in files:
        try:
            with item.open("rb") as handle:
                raw = handle.read(MAX_CUCM_CSV_FILE_BYTES + 1)
            if len(raw) > MAX_CUCM_CSV_FILE_BYTES:
                continue
            text = raw.decode("utf-8-sig", errors="replace")
            for row in csv.DictReader(io.StringIO(text, newline="")):
                rows.append(dict(row))
                if len(rows) >= MAX_CUCM_ROWS:
                    return rows
        except (OSError, csv.Error):
            continue
    return rows


def _cucm_quality_by_call(path: str) -> dict[str, dict[str, float]]:
    grouped: dict[str, dict[str, float]] = {}
    for row in _cucm_csv_rows(path, file_limit=40):
        key = _cucm_call_key(row)
        if not key:
            continue
        received = _parse_float(row.get("packetsReceived", ""))
        lost = _parse_float(row.get("numberPacketsLost", ""))
        loss = (lost / (received + lost) * 100) if received + lost > 0 else 0.0
        current = grouped.setdefault(key, {})
        current["packet_loss_percent"] = max(current.get("packet_loss_percent", 0.0), loss)
        current["jitter_ms"] = max(current.get("jitter_ms", 0.0), _parse_float(row.get("jitter", "")))
        current["latency_ms"] = max(current.get("latency_ms", 0.0), _parse_float(row.get("latency", "")))
    return grouped


def _cucm_call_key(row: dict[str, str]) -> str:
    manager = row.get("globalCallID_callManagerId", "").strip()
    call = row.get("globalCallID_callId", "").strip()
    return f"{manager}:{call}" if manager or call else ""


def _parse_float(value: object) -> float:
    try:
        return float(str(value or "0"))
    except (TypeError, ValueError):
        return 0.0


def _count_csv_files(root: Path) -> int:
    if not _is_dir(root):
        return 0
    try:
        return len(_recent_tree_files(root, "*.csv", MAX_CUCM_ENTRIES_SCANNED))
    except OSError:
        return 0


def _recent_tree_files(root: Path, pattern: str, limit: int) -> list[Path]:
    if limit <= 0:
        return []
    newest: list[tuple[float, int, Path]] = []
    pending = [root]
    scanned = 0
    sequence = 0
    while pending and scanned < MAX_CUCM_ENTRIES_SCANNED:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > MAX_CUCM_ENTRIES_SCANNED:
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False) or not fnmatch.fnmatch(
                            entry.name.lower(), pattern.lower()
                        ):
                            continue
                        modified = entry.stat(follow_symlinks=False).st_mtime
                    except OSError:
                        continue
                    candidate = (modified, sequence, Path(entry.path))
                    sequence += 1
                    if len(newest) < limit:
                        heapq.heappush(newest, candidate)
                    elif candidate[:2] > newest[0][:2]:
                        heapq.heapreplace(newest, candidate)
        except OSError:
            continue
    newest.sort(reverse=True)
    return [item[2] for item in newest]


def _recent_cdr_rows(path: Path, *, limit: int) -> list[list[str]]:
    """Read a bounded tail of an append-only Asterisk CDR file.

    Large installations can keep years of rows in Master.csv. Reading that
    complete file for every history refresh makes recent-call visibility scale
    with the lifetime of the PBX instead of the requested result size.
    """
    target_bytes = min(16 * 1024 * 1024, max(1024 * 1024, limit * 2048 * 3))
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        start = max(0, size - target_bytes)
        handle.seek(start)
        raw = handle.read()
    if start:
        newline = raw.find(b"\n")
        raw = raw[newline + 1:] if newline >= 0 else b""
    text = raw.decode("utf-8", errors="replace")
    return list(csv.reader(io.StringIO(text, newline="")))


def interpreted_call_kind(call: CdrCall) -> str:
    disposition = call.disposition.upper()
    if disposition in MISSED_CDR_DISPOSITIONS:
        return "missed"
    if disposition != "ANSWERED":
        return ""
    if _looks_like_ivr_reached(call):
        return IVR_REACHED_KIND
    return "answered"


def _looks_like_ivr_reached(call: CdrCall) -> bool:
    context = call.context.lower()
    last_app = call.last_app.lower()
    last_data = call.last_data.lower()
    destination = call.destination.strip().lower()
    has_human_channel = bool(call.destination_channel.strip())

    if has_human_channel:
        return False

    if any(marker in context for marker in ("ivr", "menu", "autoattendant", "auto-attendant")):
        return True

    if destination in {"s", "i", "t", "h"} and last_app in {
        "answer",
        "background",
        "backgroun",
        "playback",
        "read",
        "waitexten",
    }:
        return True

    return "ivr" in last_data or "menu" in last_data


def read_recent_voicemails(path: str, *, limit: int = 20) -> list[VoicemailMessage]:
    voicemail_root = Path(path)
    if not _is_dir(voicemail_root):
        return []

    messages: list[VoicemailMessage] = []
    try:
        message_files = sorted(
            voicemail_root.glob("**/INBOX/msg*.txt"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []

    for message_file in message_files[:limit]:
        metadata = _read_voicemail_metadata(message_file)
        mailbox = _mailbox_from_path(message_file)
        messages.append(
            VoicemailMessage(
                mailbox=mailbox,
                caller=metadata.get("callerid", "").strip('"') or "A caller",
                created_at=_parse_timestamp(metadata.get("origtime", "")),
            )
        )

    return messages


def history_diagnostics(cdr_csv_path: str, voicemail_path: str) -> dict[str, object]:
    cdr_path = Path(cdr_csv_path)
    voicemail_root = Path(voicemail_path)
    cdr_exists = _is_file(cdr_path)
    voicemail_exists = _is_dir(voicemail_root)
    cdr_access_error = _access_error(cdr_path, "file")
    voicemail_access_error = _access_error(voicemail_root, "dir")

    return {
        "cdrCsvPath": str(cdr_path),
        "cdrCsvExists": cdr_exists,
        "cdrCsvReadable": _is_readable_file(cdr_path),
        "cdrCsvAccessError": cdr_access_error,
        "cdrCsvSizeBytes": _file_size(cdr_path) if cdr_exists else 0,
        "cdrRecentRowsReadable": len(read_recent_cdr_calls(str(cdr_path), limit=5)),
        "voicemailPath": str(voicemail_root),
        "voicemailPathExists": voicemail_exists,
        "voicemailPathReadable": _is_readable_dir(voicemail_root),
        "voicemailPathAccessError": voicemail_access_error,
        "voicemailMessagesReadable": len(
            read_recent_voicemails(str(voicemail_root), limit=5)
        ),
    }


def read_recent_security_events(
    path: str,
    *,
    window_minutes: int = 15,
    limit: int = 100,
    now: datetime | None = None,
) -> list[SecurityEvent]:
    security_path = Path(path)
    if not _is_file(security_path):
        return []
    try:
        with security_path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - 262_144))
            raw = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return []

    cutoff = (now or datetime.now()) - timedelta(minutes=window_minutes)
    events: list[SecurityEvent] = []
    for line in raw.splitlines()[-limit * 10 :]:
        event = _security_event_from_line(line)
        if event is None:
            continue
        # Lines without a recognizable timestamp are excluded so an old entry
        # cannot become a permanent Security signal.
        if event.occurred_at is None or event.occurred_at < cutoff:
            continue
        events.append(event)
    return events[-limit:]


def security_diagnostics(path: str) -> dict[str, object]:
    security_path = Path(path)
    exists = _is_file(security_path)
    return {
        "securityLogPath": str(security_path),
        "securityLogExists": exists,
        "securityLogReadable": _is_readable_file(security_path),
        "securityLogAccessError": _access_error(security_path, "file"),
        "recentSecurityEvents": len(read_recent_security_events(str(security_path))),
    }


def _security_event_from_line(line: str) -> SecurityEvent | None:
    event_match = _SECURITY_EVENT_PATTERN.search(line)
    if event_match is None or event_match.group(1) not in _SUPPORTED_SECURITY_EVENTS:
        return None
    service_match = _SECURITY_SERVICE_PATTERN.search(line)
    return SecurityEvent(
        kind=event_match.group(1),
        service=service_match.group(1) if service_match else "PBX",
        occurred_at=_security_log_time(line),
    )


def _security_log_time(line: str) -> datetime | None:
    match = _SECURITY_LOG_TIME_PATTERN.match(line)
    if match is None:
        return None
    value = match.group(1).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value[:19], fmt)
        except ValueError:
            continue
    return None


def _read_voicemail_metadata(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            metadata[key.strip()] = value.strip()
    except OSError:
        return {}
    return metadata


def _is_readable_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            handle.read(1)
        return True
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _access_error(path: Path, kind: str) -> str:
    try:
        if kind == "dir":
            path.is_dir()
        else:
            path.is_file()
    except OSError:
        label = "folder" if kind == "dir" else "file"
        return f"The configured {label} cannot be accessed."
    return ""


def _is_readable_dir(path: Path) -> bool:
    try:
        next(path.iterdir(), None)
        return True
    except OSError:
        return False


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _mailbox_from_path(path: Path) -> str:
    parts = path.parts
    if "INBOX" not in parts:
        return ""
    inbox_index = parts.index("INBOX")
    if inbox_index == 0:
        return ""
    return parts[inbox_index - 1]


def _parse_datetime(raw: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _parse_timestamp(raw: str) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(raw))
    except (TypeError, ValueError, OSError):
        return None


def _parse_int(raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        return 0


def _recording_id_from_row(row: list[str]) -> str:
    # CDR userfield is the only standard CSV location that explicitly denotes
    # a recording filename. Unique IDs exist for every call, recorded or not.
    if len(row) > 17 and row[17].strip():
        return _recording_filename(row[17])
    return ""


def _recording_filename(value: str) -> str:
    return value.strip().replace("\\", "/").rsplit("/", 1)[-1]
