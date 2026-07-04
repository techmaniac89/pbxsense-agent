from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

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


@dataclass(frozen=True)
class VoicemailMessage:
    mailbox: str
    caller: str
    created_at: datetime | None


def read_recent_cdr_calls(path: str, *, limit: int = 30) -> list[CdrCall]:
    cdr_path = Path(path)
    if not _is_file(cdr_path):
        return []

    rows: list[list[str]] = []
    try:
        with cdr_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            rows = list(csv.reader(handle))
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
            )
        )

    calls.sort(key=lambda call: call.started_at or datetime.min, reverse=True)
    return calls[:limit]


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
    except OSError as exc:
        return str(exc)
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
