"""Normalize source events and assign sequence IDs before any selection."""

from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid5

from vmbox.collect.trace import TraceHeader, TraceRecord
from vmbox.normalize.sequence import SequenceCounter
from vmbox.schema import EVENT_CATEGORIES, CaptureInfo, Event, ProcessInfo


def _pid(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, (int, str)) or isinstance(value, bool) or str(value) == "":
        raise ValueError("invalid PID")
    result = int(value)
    if result < 0:
        raise ValueError("negative PID")
    return result


def _timestamp(record: TraceRecord) -> tuple[
    int, Literal["etw_qpc", "sysmon_utc", "wallclock", "replay"]
]:
    if record.source == "sysmon":
        value = record.payload.get("UtcTime")
        if type(value) is str:
            try:
                parsed = datetime.fromisoformat(value.replace(" ", "T").replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=UTC)
                epoch = datetime(1970, 1, 1, tzinfo=UTC)
                delta = parsed - epoch
                return ((delta.days * 86400 + delta.seconds) * 1_000_000_000
                        + delta.microseconds * 1000), "sysmon_utc"
            except ValueError:
                pass
    # ETW QPC conversion is unverified until run on Windows VM. Receipt time
    # is explicit wallclock fallback; never label it etw_qpc.
    return record.receipt_ts_ns, "wallclock"


class Normalizer:
    def __init__(self, header: TraceHeader) -> None:
        self.header = header
        self._sequence = SequenceCounter()

    def normalize(self, record: TraceRecord) -> Event:
        if record.source not in self.header.sources:
            raise ValueError("source absent from trace header")
        if record.event_type not in EVENT_CATEGORIES:
            raise ValueError(f"unknown event type {record.event_type!r}")
        seq = self._sequence.assign()
        data = record.payload
        pid = _pid(data.get("pid", data.get("ProcessId", data.get("SourceProcessId"))))
        ppid = _pid(data.get("ppid", data.get("ParentProcessId")))
        image = data.get("process", data.get("Image", data.get("SourceImage")))
        if image is not None and (type(image) is not str or not image):
            raise ValueError("invalid process image")
        cmdline = data.get("CommandLine")
        if cmdline is not None and type(cmdline) is not str:
            raise ValueError("invalid command line")
        cmd_hash = data.get("CommandLineHash")
        if cmd_hash is not None and type(cmd_hash) is not str:
            raise ValueError("invalid command line hash")
        if cmdline is not None:
            computed = "sha256:" + sha256(cmdline.encode("utf-8")).hexdigest()
            if cmd_hash is not None and cmd_hash != computed:
                raise ValueError("command-line hash mismatch")
            cmd_hash = computed
        process = ProcessInfo(image, cmd_hash, cmdline) if image is not None else None
        category = EVENT_CATEGORIES[record.event_type]
        partial = category != "meta" and (pid is None or ppid is None or process is None
                                           or cmd_hash is None)
        ts_ns, ts_source = _timestamp(record)
        return Event(
            schema_version=1,
            event_id=str(uuid5(UUID(self.header.session_id), str(seq))),
            session_id=self.header.session_id, boot_id=self.header.boot_id, seq=seq,
            ts_ns=ts_ns, ts_source=ts_source, event_type=record.event_type,
            category=category, pid=pid, ppid=ppid, process=process,
            data={key: value for key, value in data.items()
                  if key not in {"CommandLine", "CommandLineHash"}},
            provenance="observed",
            capture=CaptureInfo(record.source, "partial" if partial else "ok",
                                self.header.collector_version),
            priority=None, tags=[],
        )
