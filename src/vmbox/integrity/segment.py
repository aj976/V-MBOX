"""Validate sealed segment bytes and classify damage."""

import json
import re
import struct
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from vmbox.canonical import canonical_json
from vmbox.schema import Event
from vmbox.store.segment import SegmentFooter, SegmentHeader

_LENGTH = struct.Struct(">I")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class SegmentVerification:
    status: Literal["ok", "incomplete", "tampered"]
    reason: str | None
    events: list[Event]
    header: SegmentHeader | None
    footer: SegmentFooter | None


def _canonical_object(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8"))
    if type(value) is not dict or canonical_json(value) != raw:
        raise ValueError("noncanonical JSON")
    return value


def verify_segment(path: Path, expected_prev_hash: str) -> SegmentVerification:
    if not _HASH.fullmatch(expected_prev_hash):
        raise ValueError("invalid expected previous hash")
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return SegmentVerification("incomplete", "segment missing", [], None, None)
    header_end = data.find(b"\n")
    if header_end < 0:
        return SegmentVerification("incomplete", "header line torn", [], None, None)
    try:
        header = SegmentHeader.from_dict(_canonical_object(data[:header_end]))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return SegmentVerification("tampered", "header invalid", [], None, None)
    if header.prev_hash != expected_prev_hash:
        return SegmentVerification("tampered", "previous hash mismatch", [], header, None)
    position = header_end + 1
    body_start = position
    events: list[Event] = []
    for _ in range(header.record_count):
        if position + _LENGTH.size > len(data):
            return SegmentVerification("incomplete", "body frame length torn", events, header, None)
        length = _LENGTH.unpack_from(data, position)[0]
        position += _LENGTH.size
        if position + length > len(data):
            return SegmentVerification("incomplete", "body frame torn", events, header, None)
        try:
            event = Event.from_dict(_canonical_object(data[position:position + length]))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return SegmentVerification("tampered", "body event invalid", events, header, None)
        events.append(event)
        position += length
    body = data[body_start:position]
    if not data[position:].endswith(b"\n"):
        return SegmentVerification("incomplete", "footer line torn", events, header, None)
    try:
        footer = SegmentFooter.from_dict(_canonical_object(data[position:-1]))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return SegmentVerification("tampered", "footer invalid", events, header, None)
    if (len(events) != header.record_count or events[0].seq != header.seq_start
            or events[-1].seq != header.seq_end
            or any(left.seq >= right.seq for left, right in zip(events, events[1:], strict=False))
            or any(event.session_id != header.session_id for event in events)
            or min(event.ts_ns for event in events) != header.ts_start_ns
            or max(event.ts_ns for event in events) != header.ts_end_ns):
        return SegmentVerification("tampered", "header and events disagree", events, header,
                                   footer)
    if footer.body_sha256 != "sha256:" + sha256(body).hexdigest():
        return SegmentVerification("tampered", "body hash mismatch", events, header, footer)
    previous_digest = bytes.fromhex(expected_prev_hash.removeprefix("sha256:"))
    actual_chain = "sha256:" + sha256(previous_digest + data[:position]).hexdigest()
    if footer.segment_hash != actual_chain:
        return SegmentVerification("tampered", "segment hash mismatch", events, header,
                                   footer)
    return SegmentVerification("ok", None, events, header, footer)
