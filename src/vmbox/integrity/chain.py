"""Verify a session's surviving segment chain across tombstones."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.segment import verify_segment
from vmbox.integrity.tombstone import verify_tombstone
from vmbox.schema import SessionManifest

_NAME = re.compile(r"seg_([0-9]{8})\.(vseg|tomb)\Z")


@dataclass(frozen=True)
class ChainEntry:
    index: int
    kind: Literal["segment", "tombstone"]
    segment_hash: str


@dataclass(frozen=True)
class ChainVerification:
    status: Literal["ok", "incomplete", "tampered"]
    reason: str | None
    entries: list[ChainEntry]
    last_hash: str


def verify_chain(directory: Path, manifest: SessionManifest) -> ChainVerification:
    """No receipt means trailing deletion cannot be detected; M4 adds that check."""
    previous = "sha256:" + manifest_genesis(manifest).hex()
    entries: list[ChainEntry] = []
    files: dict[int, dict[str, Path]] = {}
    for path in directory.glob("seg_*.*"):
        if path.name.endswith(".tmp"):
            return ChainVerification("incomplete", "unsealed temporary segment", entries,
                                     previous)
        match = _NAME.fullmatch(path.name)
        if match is None:
            return ChainVerification("incomplete", "unrecognized segment file", entries,
                                     previous)
        index = int(match.group(1))
        files.setdefault(index, {})[match.group(2)] = path
    for index in range(max(files, default=-1) + 1):
        representations = files.get(index, {})
        if len(representations) == 0:
            return ChainVerification("incomplete", f"segment {index} missing", entries,
                                     previous)
        if len(representations) > 1:
            return ChainVerification("incomplete", f"segment {index} has two representations",
                                     entries, previous)
        if "vseg" in representations:
            result = verify_segment(representations["vseg"], previous)
            if result.status != "ok" or result.header is None or result.footer is None:
                return ChainVerification(result.status, result.reason, entries, previous)
            if result.header.index != index or result.header.session_id != manifest.session_id:
                return ChainVerification("tampered", "segment index/session mismatch", entries,
                                         previous)
            previous = result.footer.segment_hash
            entries.append(ChainEntry(index, "segment", previous))
        else:
            result_tomb = verify_tombstone(representations["tomb"], previous, index)
            if result_tomb.status != "metadata_valid" or result_tomb.tombstone is None:
                status: Literal["incomplete", "tampered"] = (
                    "incomplete" if result_tomb.status == "incomplete" else "tampered")
                return ChainVerification(status, result_tomb.reason, entries, previous)
            previous = result_tomb.tombstone.segment_hash
            entries.append(ChainEntry(index, "tombstone", previous))
    return ChainVerification("ok", None, entries, previous)
