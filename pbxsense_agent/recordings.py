from __future__ import annotations

from pathlib import Path
import re


_AUDIO_SUFFIXES = {".wav", ".mp3", ".ogg", ".gsm", ".ulaw", ".alaw", ".flac"}


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
        for candidate in directory.rglob("*"):
            if not candidate.is_file() or candidate.suffix.lower() not in _AUDIO_SUFFIXES:
                continue
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
