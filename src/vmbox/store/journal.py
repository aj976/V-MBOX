"""Fixed-capacity CRC journal ring specified in docs/SCHEMA.md §3."""

from __future__ import annotations

import json
import os
import struct
import zlib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO

from vmbox.canonical import canonical_json
from vmbox.schema import Event

_SLOT_BODY = struct.Struct(">QIIIQ")
_SLOT = struct.Struct(">QIIIQI")
_FRAME = struct.Struct(">II")
_CONTROL_SIZE = 2 * _SLOT.size


@dataclass(frozen=True)
class _Cursor:
    generation: int
    oldest_offset: int
    write_offset: int
    used_bytes: int
    evicted_frames: int


@dataclass(frozen=True)
class JournalRecovery:
    events: list[Event]
    evicted_frames: int
    incomplete_reason: str | None


def _slot_bytes(cursor: _Cursor) -> bytes:
    body = _SLOT_BODY.pack(cursor.generation, cursor.oldest_offset,
                           cursor.write_offset, cursor.used_bytes, cursor.evicted_frames)
    return body + struct.pack(">I", zlib.crc32(body))


def _decode_slot(raw: bytes, data_size: int) -> _Cursor | None:
    if len(raw) != _SLOT.size:
        return None
    generation, oldest, write, used, evicted, crc = _SLOT.unpack(raw)
    if zlib.crc32(raw[:-4]) != crc:
        return None
    if oldest >= data_size or write >= data_size or used >= data_size:
        return None
    if used == 0 and oldest != write:
        return None
    return _Cursor(generation, oldest, write, used, evicted)


def _load_cursor(stream: BinaryIO, data_size: int) -> _Cursor:
    stream.seek(0)
    raw = stream.read(_CONTROL_SIZE)
    candidates = [_decode_slot(raw[i:i + _SLOT.size], data_size)
                  for i in (0, _SLOT.size)]
    valid = [candidate for candidate in candidates if candidate is not None]
    if not valid:
        raise ValueError("journal cursor is missing or corrupt")
    return max(valid, key=lambda candidate: candidate.generation)


def _read_entry(stream: BinaryIO, offset: int, data_size: int) -> tuple[Event | None, int]:
    tail = data_size - offset
    stream.seek(_CONTROL_SIZE + offset)
    if tail < _FRAME.size:
        if stream.read(tail) != bytes(tail):
            raise ValueError("journal wrap padding is corrupt")
        return None, tail
    frame_header = stream.read(_FRAME.size)
    if len(frame_header) != _FRAME.size:
        raise ValueError("short journal frame header")
    length, crc = _FRAME.unpack(frame_header)
    if length == 0:
        if crc != 0 or stream.read(tail - _FRAME.size) != bytes(tail - _FRAME.size):
            raise ValueError("journal wrap marker is corrupt")
        return None, tail
    if length > tail - _FRAME.size:
        raise ValueError("journal frame extends past wrap")
    payload = stream.read(length)
    if len(payload) != length or zlib.crc32(payload) != crc:
        raise ValueError("journal frame CRC or length mismatch")
    try:
        data = json.loads(payload.decode("utf-8"))
        if canonical_json(data) != payload:
            raise ValueError("noncanonical journal payload")
        event = Event.from_dict(data)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("invalid journal event") from exc
    return event, _FRAME.size + length


def _scan(stream: BinaryIO, cursor: _Cursor, data_size: int) -> JournalRecovery:
    events: list[Event] = []
    remaining = cursor.used_bytes
    offset = cursor.oldest_offset
    while remaining:
        try:
            event, length = _read_entry(stream, offset, data_size)
        except ValueError as exc:
            return JournalRecovery(events, cursor.evicted_frames, str(exc))
        if length > remaining:
            return JournalRecovery(events, cursor.evicted_frames,
                                   "journal entry exceeds live window")
        if event is not None:
            if events and (event.session_id != events[0].session_id
                           or event.seq <= events[-1].seq):
                return JournalRecovery(events, cursor.evicted_frames,
                                       "journal session or sequence order invalid")
            events.append(event)
        remaining -= length
        offset = (offset + length) % data_size
    if offset != cursor.write_offset:
        return JournalRecovery(events, cursor.evicted_frames,
                               "journal cursor does not match frame window")
    return JournalRecovery(events, cursor.evicted_frames, None)


def recover_journal(path: Path) -> JournalRecovery:
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        data_size = stream.tell() - _CONTROL_SIZE
        if data_size < 16:
            return JournalRecovery([], 0, "journal too short")
        try:
            cursor = _load_cursor(stream, data_size)
        except ValueError as exc:
            return JournalRecovery([], 0, str(exc))
        return _scan(stream, cursor, data_size)


def create_journal(path: Path, journal_bytes: int) -> None:
    if journal_bytes < _CONTROL_SIZE + 16:
        raise ValueError("journal capacity too small")
    with path.open("xb") as stream:
        stream.truncate(journal_bytes)
        stream.seek(0)
        stream.write(_slot_bytes(_Cursor(0, 0, 0, 0, 0)))
        stream.flush()
        os.fsync(stream.fileno())


def _advance_oldest(stream: BinaryIO, cursor: _Cursor, data_size: int) -> _Cursor:
    if cursor.used_bytes == 0:
        raise ValueError("cannot evict an empty journal")
    event, length = _read_entry(stream, cursor.oldest_offset, data_size)
    if length > cursor.used_bytes:
        raise ValueError("journal live window is corrupt")
    oldest = (cursor.oldest_offset + length) % data_size
    used = cursor.used_bytes - length
    return replace(cursor, oldest_offset=oldest, used_bytes=used,
                   evicted_frames=cursor.evicted_frames + (event is not None))


def append_journal_many(path: Path, events: Iterable[Event]) -> int:
    """Append a stream while validating the existing ring only once.

    Every frame and cursor is still flushed in the documented order. Recovery
    revalidates the entire live window; no cached state is trusted across calls.
    """
    with path.open("r+b") as stream:
        stream.seek(0, os.SEEK_END)
        data_size = stream.tell() - _CONTROL_SIZE
        cursor = _load_cursor(stream, data_size)
        recovered = _scan(stream, cursor, data_size)
        if recovered.incomplete_reason is not None:
            raise ValueError("cannot append to incomplete journal")
        last = recovered.events[-1] if recovered.events else None
        for event in events:
            if last is not None and (event.session_id != last.session_id
                                     or event.seq <= last.seq):
                raise ValueError("journal events must have ascending seq in one session")
            payload = event.to_json()
            frame = _FRAME.pack(len(payload), zlib.crc32(payload)) + payload
            if len(frame) >= data_size:
                raise ValueError("event frame exceeds journal capacity")
            while True:
                if cursor.used_bytes == 0:
                    cursor = replace(cursor, oldest_offset=0, write_offset=0)
                tail = data_size - cursor.write_offset
                free = data_size - cursor.used_bytes
                if cursor.used_bytes == 0:
                    padding = 0
                    break
                if cursor.write_offset < cursor.oldest_offset:
                    if len(frame) < cursor.oldest_offset - cursor.write_offset:
                        padding = 0
                        break
                elif len(frame) <= tail and len(frame) < free:
                    padding = 0
                    break
                elif len(frame) > tail and tail + len(frame) < free:
                    padding = tail
                    break
                cursor = _advance_oldest(stream, cursor, data_size)
            if padding:
                stream.seek(_CONTROL_SIZE + cursor.write_offset)
                if padding >= _FRAME.size:
                    stream.write(_FRAME.pack(0, 0))
                    stream.write(bytes(padding - _FRAME.size))
                else:
                    stream.write(bytes(padding))
            write_offset = (cursor.write_offset + padding) % data_size
            stream.seek(_CONTROL_SIZE + write_offset)
            stream.write(frame)
            stream.flush()
            os.fsync(stream.fileno())
            new_write = (write_offset + len(frame)) % data_size
            cursor = replace(cursor, generation=cursor.generation + 1,
                             write_offset=new_write, used_bytes=cursor.used_bytes + padding
                             + len(frame))
            stream.seek((cursor.generation % 2) * _SLOT.size)
            stream.write(_slot_bytes(cursor))
            stream.flush()
            os.fsync(stream.fileno())
            last = event
        return cursor.evicted_frames


def append_journal(path: Path, event: Event) -> int:
    """Append one canonical event and return cumulative ring evictions."""
    return append_journal_many(path, [event])
