"""Validate surviving tombstone metadata, not deleted event content."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from vmbox.canonical import canonical_json
from vmbox.schema import Tombstone


@dataclass(frozen=True)
class TombstoneVerification:
    status: Literal["metadata_valid", "incomplete", "tampered"]
    reason: str | None
    tombstone: Tombstone | None


def verify_tombstone(path: Path, expected_prev_hash: str, index: int) -> TombstoneVerification:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return TombstoneVerification("incomplete", "tombstone missing", None)
    if not raw.endswith(b"\n"):
        return TombstoneVerification("incomplete", "tombstone line torn", None)
    try:
        data = json.loads(raw[:-1].decode("utf-8"))
        if type(data) is not dict or canonical_json(data) + b"\n" != raw:
            raise ValueError("noncanonical tombstone")
        tombstone = Tombstone.from_dict(data)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return TombstoneVerification("tampered", "tombstone metadata invalid", None)
    if tombstone.prev_hash != expected_prev_hash or tombstone.index != index:
        return TombstoneVerification("tampered", "tombstone chain/index mismatch", tombstone)
    return TombstoneVerification("metadata_valid", None, tombstone)
