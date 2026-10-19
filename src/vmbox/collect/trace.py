"""Write-once canonical JSON Lines raw traces; see docs/SCHEMA.md."""

import json
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from time import time_ns
from typing import Any
from uuid import UUID

from vmbox.canonical import canonical_json
from vmbox.collect.source import RawEvent

_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class TraceHeader:
    trace_format_version: int
    trace_id: str
    session_id: str
    boot_id: str
    sources: list[str]
    collector_version: str
    config_hash: str
    sysmon_config_hash: str | None
    host: dict[str, str]
    raw_cmdline_opt_in: bool

    def __post_init__(self) -> None:
        if self.trace_format_version != 1:
            raise ValueError("unsupported trace format")
        UUID(self.trace_id)
        UUID(self.session_id)
        if not self.boot_id or not self.sources or len(self.sources) != len(set(self.sources)):
            raise ValueError("invalid boot ID or source list")
        if any(not source for source in self.sources) or not self.collector_version:
            raise ValueError("invalid source or collector version")
        if not _HASH.fullmatch(self.config_hash):
            raise ValueError("invalid config hash")
        if self.sysmon_config_hash is not None and not _HASH.fullmatch(self.sysmon_config_hash):
            raise ValueError("invalid Sysmon config hash")
        if "sysmon" in self.sources and self.sysmon_config_hash is None:
            raise ValueError("Sysmon config hash required")
        if set(self.host) != {"windows_build"} or not self.host["windows_build"]:
            raise ValueError("host must contain only sanitized windows_build")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TraceHeader":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid trace header fields")
        if (type(value["trace_format_version"]) is not int
                or type(value["sources"]) is not list
                or not all(type(x) is str for x in value["sources"])
                or type(value["host"]) is not dict
                or not all(type(k) is str and type(v) is str
                           for k, v in value["host"].items())
                or type(value["raw_cmdline_opt_in"]) is not bool
                or not all(type(value[k]) is str for k in (
                    "trace_id", "session_id", "boot_id", "collector_version", "config_hash"))
                or (value["sysmon_config_hash"] is not None
                    and type(value["sysmon_config_hash"]) is not str)):
            raise ValueError("invalid trace header types")
        return cls(**value)


@dataclass(frozen=True)
class TraceRecord:
    source: str
    event_type: str
    receipt_ts_ns: int
    payload: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TraceRecord":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid trace event fields")
        if (type(value["source"]) is not str or not value["source"]
                or type(value["event_type"]) is not str or not value["event_type"]
                or type(value["receipt_ts_ns"]) is not int or value["receipt_ts_ns"] < 0
                or type(value["payload"]) is not dict):
            raise ValueError("invalid trace event types")
        return cls(**value)


def _line(value: object) -> bytes:
    return canonical_json(value) + b"\n"


def _sanitize(raw: RawEvent, header: TraceHeader, receipt_ts_ns: int) -> TraceRecord:
    if raw.source not in header.sources:
        raise ValueError(f"source {raw.source!r} is absent from trace header")
    payload = raw.payload.copy()
    command = payload.get("CommandLine")
    if command is not None:
        if type(command) is not str:
            raise ValueError("CommandLine must be text")
        digest = "sha256:" + sha256(command.encode("utf-8")).hexdigest()
        existing = payload.get("CommandLineHash")
        if existing is not None and existing != digest:
            raise ValueError("CommandLineHash mismatch")
        payload["CommandLineHash"] = digest
        if not header.raw_cmdline_opt_in:
            del payload["CommandLine"]
    return TraceRecord.from_dict({"source": raw.source, "event_type": raw.event_type,
                                  "receipt_ts_ns": receipt_ts_ns, "payload": payload})


def write_trace(path: Path, header: TraceHeader, events: Iterable[RawEvent],
                *, receipt_clock: Any = time_ns) -> str:
    """Write once. Missing sidecar after interruption means an incomplete trace."""
    if header.raw_cmdline_opt_in and not path.name.endswith(".local.jsonl"):
        raise ValueError("raw command lines require a .local.jsonl trace")
    sidecar = Path(str(path) + ".sha256")
    if path.exists() or sidecar.exists():
        raise FileExistsError(path)
    digest = sha256()
    with path.open("xb") as stream:
        header_line = _line(header)
        stream.write(header_line)
        digest.update(header_line)
        for raw in events:
            line = _line(_sanitize(raw, header, receipt_clock()))
            stream.write(line)
            digest.update(line)
        stream.flush()
        os.fsync(stream.fileno())
    result = "sha256:" + digest.hexdigest()
    with sidecar.open("xb") as stream:
        stream.write(_line({"sha256": result}))
        stream.flush()
        os.fsync(stream.fileno())
    return result


def _decode_line(line: bytes) -> dict[str, Any]:
    if not line.endswith(b"\n"):
        raise ValueError("torn trace line")
    value = json.loads(line.decode("utf-8"))
    if type(value) is not dict or _line(value) != line:
        raise ValueError("noncanonical trace line")
    return value


def read_trace(path: Path) -> tuple[TraceHeader, list[TraceRecord]]:
    """Verify the entire write-once trace before returning any events."""
    sidecar = Path(str(path) + ".sha256")
    try:
        data = path.read_bytes()
        sidecar_data = sidecar.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError("incomplete trace: file or sidecar missing") from exc
    digest = "sha256:" + sha256(data).hexdigest()
    if sidecar_data != _line({"sha256": digest}):
        raise ValueError("trace digest mismatch or invalid sidecar")
    lines = data.splitlines(keepends=True)
    if not lines:
        raise ValueError("empty trace")
    header = TraceHeader.from_dict(_decode_line(lines[0]))
    records = [TraceRecord.from_dict(_decode_line(line)) for line in lines[1:]]
    if any(record.source not in header.sources for record in records):
        raise ValueError("event source absent from header")
    if not header.raw_cmdline_opt_in and any(
        "CommandLine" in record.payload for record in records
    ):
        raise ValueError("raw command line in default trace")
    return header, records
