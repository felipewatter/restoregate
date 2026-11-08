"""Portable archive path validation; rejects ambiguous and unsafe names."""
from __future__ import annotations

import re
import unicodedata

_WINDOWS_DEVICES = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def validate_member_path(name: str) -> str | None:
    if not name or name.startswith("/") or "\\" in name:
        return "absolute, empty, or backslash-containing path"
    if unicodedata.normalize("NFC", name) != name:
        return "non-NFC Unicode path"
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        return "control character in path"
    if ":" in name:
        return "colon (drive or NTFS alternate data stream)"
    if len(name) > 4096:
        return "path exceeds 4096 characters"
    for segment in name.split("/"):
        if segment in ("", ".", ".."):
            return "empty, dot or parent path component"
        if segment[-1:] in (" ", "."):
            return "trailing dot or space (Windows ambiguity)"
        if segment.split(".", 1)[0].casefold() in _WINDOWS_DEVICES:
            return "Windows reserved device name"
        if any(c in '<>"|?*' for c in segment):
            return "non-portable special character"
    return None
