from __future__ import annotations

from pathlib import Path
import os
import re
import threading
import time


_AUDIO_SUFFIXES = {".wav", ".mp3", ".ogg", ".gsm", ".ulaw", ".alaw", ".flac"}
_INDEX_TTL_SECONDS = 15
_MAX_INDEXED_FILES = 50_000
_index_lock = threading.Lock()
_index_cache: dict[str, tuple[float, tuple[Path, ...]]] = {}


def _recording_index(directory: Path) -> tuple[Path, ...]:
    key = str(directory.resolve())
    now = time.monotonic()
    with _index_lock:
        cached = _index_cache.get(key)
        if cached and now - cached[0] < _INDEX_TTL_SECONDS:
            return cached[1]
    found: list[Path] = []
    for current, directories, files in os.walk(directory, followlinks=False):
        directories[:] = [
            name for name in directories if not (Path(current) / name).is_symlink()
        ]
        for name in files:
            candidate = Path(current) / name
            if candidate.suffix.lower() not in _AUDIO_SUFFIXES or candidate.is_symlink():
                continue
            found.append(candidate)
            if len(found) >= _MAX_INDEXED_FILES:
                break
        if len(found) >= _MAX_INDEXED_FILES:
            break
    result = tuple(found)
    with _index_lock:
        _index_cache[key] = (now, result)
        if len(_index_cache) > 8:
            oldest = min(_index_cache, key=lambda item: _index_cache[item][0])
            _index_cache.pop(oldest, None)
    return result


def find_recording(root: str, recording_id: str) -> Path | None:
    """Find an audio file under a configured recording root without exposing paths."""
    if not root or not recording_id:
        return None
    try:
        directory = Path(root)
        if not directory.is_dir():
            return None
        requested_name = Path(recording_id).name.lower()
        requested_stem = Path(requested_name).stem
        exact: list[Path] = []
        bounded: list[Path] = []
        boundary_pattern = re.compile(
            rf"(?<![a-z0-9]){re.escape(requested_stem)}(?![a-z0-9])",
            re.IGNORECASE,
        )
        for candidate in _recording_index(directory):
            candidate_name = candidate.name.lower()
            if candidate_name == requested_name or candidate.stem.lower() == requested_stem:
                exact.append(candidate)
            elif requested_stem and boundary_pattern.search(candidate.stem):
                bounded.append(candidate)
        matches = exact or bounded
        # Ambiguous identifiers must not play an unrelated call recording.
        return matches[0] if len(matches) == 1 else None
    except OSError:
        return None
    return None
