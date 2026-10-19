"""Write-once sealed segment encoding from docs/SCHEMA.md §4."""

from __future__ import annotations

import os
import re
import struct
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from vmbox.canonical import canonical_json
from vmbox.schema import Event

_LENGTH = struct.Struct(">I")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class SelectionStats:
    seen: int
    kept: int
    dropped_by_policy: int
    by_type: dict[str, int]
    promoted_by_context: int

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 0 for value in (
            self.seen, self.kept, self.dropped_by_policy, self.promoted_by_context
        )):
            raise ValueError("negative or invalid selection count")
        if self.seen < self.kept + self.dropped_by_policy:
            raise ValueError("selection counts exceed seen")
        if self.promoted_by_context > self.kept:
            raise ValueError("promotions exceed kept")
        if type(self.by_type) is not dict or any(
            type(key) is not str or type(value) is not int or value < 0
            for key, value in self.by_type.items()
        ):
            raise ValueError("invalid by_type counts")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SelectionStats:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid selection_stats fields")
        return cls(**value)


@dataclass(frozen=True)
class SegmentHeader:
    schema_version: int
    session_id: str
    index: int
    seq_start: int
    seq_end: int
    record_count: int
    ts_start_ns: int
    ts_end_ns: int
    prev_hash: str
    strategy: str
    selection_stats: SelectionStats

    def __post_init__(self) -> None:
        if self.schema_version != 1 or not self.session_id or not self.strategy:
            raise ValueError("invalid segment version/session/strategy")
        if any(type(value) is not int or value < 0 for value in (
            self.index, self.seq_start, self.seq_end, self.record_count,
            self.ts_start_ns, self.ts_end_ns,
        )) or self.record_count == 0:
            raise ValueError("invalid segment index or range")
        if self.seq_start > self.seq_end or self.ts_start_ns > self.ts_end_ns:
            raise ValueError("reversed segment range")
        if not _HASH.fullmatch(self.prev_hash):
            raise ValueError("invalid previous digest")
        if type(self.selection_stats) is not SelectionStats:
            raise ValueError("invalid selection stats")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SegmentHeader:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid segment header fields")
        return cls(**{**value, "selection_stats": SelectionStats.from_dict(
            value["selection_stats"]
        )})


@dataclass(frozen=True)
class SegmentFooter:
    segment_hash: str
    body_sha256: str

    def __post_init__(self) -> None:
        if not _HASH.fullmatch(self.segment_hash) or not _HASH.fullmatch(self.body_sha256):
            raise ValueError("invalid footer digest")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SegmentFooter:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid footer fields")
        return cls(**value)


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def encode_segment(*, index: int, events: list[Event], prev_hash: str,
                   strategy: str, selection_stats: SelectionStats) -> tuple[bytes, SegmentFooter]:
    """Build exact bytes before any write so budget checks can include temp space."""
    if not events:
        raise ValueError("cannot seal empty segment")
    if any(event.session_id != events[0].session_id for event in events):
        raise ValueError("segment crosses sessions")
    if any(left.seq >= right.seq for left, right in zip(events, events[1:], strict=False)):
        raise ValueError("segment events must have ascending seq")
    if selection_stats.kept != len(events):
        raise ValueError("selection kept count does not match segment")
    header = SegmentHeader(
        schema_version=1, session_id=events[0].session_id, index=index,
        seq_start=events[0].seq, seq_end=events[-1].seq, record_count=len(events),
        ts_start_ns=min(event.ts_ns for event in events),
        ts_end_ns=max(event.ts_ns for event in events), prev_hash=prev_hash,
        strategy=strategy, selection_stats=selection_stats,
    )
    header_bytes = canonical_json(asdict(header)) + b"\n"
    body = b"".join(_LENGTH.pack(len(event.to_json())) + event.to_json() for event in events)
    previous_digest = bytes.fromhex(prev_hash.removeprefix("sha256:"))
    footer = SegmentFooter(_digest(previous_digest + header_bytes + body), _digest(body))
    final_bytes = header_bytes + body + canonical_json(asdict(footer)) + b"\n"
    return final_bytes, footer


def seal_segment(path: Path, *, index: int, events: list[Event], prev_hash: str,
                 strategy: str, selection_stats: SelectionStats) -> SegmentFooter:
    """Write temp, fsync, then rename to a never-overwritten .vseg file."""
    final_bytes, footer = encode_segment(index=index, events=events, prev_hash=prev_hash,
                                         strategy=strategy, selection_stats=selection_stats)
    temp = path.with_name(path.name + ".tmp")
    if path.exists() or temp.exists():
        raise FileExistsError(path)
    with temp.open("xb") as stream:
        stream.write(final_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    # On Windows (the target platform), os.rename refuses an existing destination.
    # VM power-loss behavior remains unverified until run on Windows VM.
    os.rename(temp, path)
    return footer
