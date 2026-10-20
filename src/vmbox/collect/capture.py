"""Sysmon-only raw trace capture; live behavior unverified until Windows VM run."""

import queue
import threading
import time
from collections.abc import Callable, Iterator
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from vmbox import __version__
from vmbox.canonical import canonical_json
from vmbox.collect.source import RawEvent, Source
from vmbox.collect.trace import TraceHeader, TraceRecord, write_trace


def make_sysmon_header(sysmon_config: bytes, boot_id: str, windows_build: str,
                       queue_capacity: int = 10000) -> TraceHeader:
    """Keep manifest and raw-trace configuration identity in one place."""
    if not sysmon_config or queue_capacity <= 0:
        raise ValueError("invalid Sysmon config or queue capacity")
    sysmon_hash = "sha256:" + sha256(sysmon_config).hexdigest()
    config = {"source": "sysmon", "queue_capacity": queue_capacity,
              "sysmon_config_hash": sysmon_hash}
    config_hash = "sha256:" + sha256(canonical_json(config)).hexdigest()
    return TraceHeader(1, str(uuid4()), str(uuid4()), boot_id,
                       ["sysmon", "collector"], __version__, config_hash,
                       sysmon_hash, {"windows_build": windows_build}, False)


def capture_sysmon_trace(path: Path, source: Source, *, duration_s: float,
                         sysmon_config: bytes, boot_id: str, windows_build: str,
                         queue_capacity: int = 10000,
                         clock: Callable[[], float] = time.monotonic,
                         receipt_clock: Callable[[], int] = time.time_ns,
                         on_ready: Callable[[], None] | None = None,
                         header: TraceHeader | None = None,
                         on_record: Callable[[TraceRecord], None] | None = None,
                         on_idle: Callable[[], None] | None = None,
                         emit_lifecycle: bool = False,
                         stop_extra: Callable[[], dict[str, int]] | None = None,
                         ) -> tuple[str, int]:
    """Capture exact source arrival order; any internal loss becomes a gap event."""
    if duration_s <= 0 or queue_capacity <= 0 or not sysmon_config:
        raise ValueError("invalid capture duration, queue or Sysmon config")
    expected = make_sysmon_header(sysmon_config, boot_id, windows_build, queue_capacity)
    header = header or expected
    if (header.sysmon_config_hash != expected.sysmon_config_hash
            or header.config_hash != expected.config_hash):
        raise ValueError("provided trace header disagrees with collector config")
    config_hash = expected.config_hash
    pending: queue.Queue[RawEvent] = queue.Queue(maxsize=queue_capacity)
    lock = threading.Lock()
    overflow = 0
    stopped = False

    def sink(event: RawEvent) -> None:
        nonlocal overflow
        try:
            pending.put_nowait(event)
        except queue.Full:
            with lock:
                overflow += 1

    def events() -> Iterator[RawEvent]:
        nonlocal stopped
        deadline = clock() + duration_s
        if emit_lifecycle:
            yield RawEvent("collector", "COLLECTOR_START",
                           {"config_hash": config_hash, "sources": ["sysmon"]})
        try:
            while clock() < deadline:
                try:
                    yield pending.get(timeout=min(0.1, max(0.0, deadline - clock())))
                except queue.Empty:
                    if on_idle is not None:
                        on_idle()
        finally:
            stopped = True
            source.stop()
        while not pending.empty():
            yield pending.get_nowait()
        if overflow:
            yield RawEvent("collector", "CAPTURE_GAP",
                           {"reason": "queue_overflow", "source": "sysmon",
                            "approx_missed": overflow})
        if emit_lifecycle:
            yield RawEvent("collector", "COLLECTOR_STOP",
                           {"config_hash": config_hash, "sources": ["sysmon"],
                            **(stop_extra() if stop_extra is not None else {})})

    source.start(sink)
    try:
        if on_ready is not None:
            on_ready()
        digest = write_trace(path, header, events(), receipt_clock=receipt_clock,
                             on_record=on_record)
    finally:
        if not stopped:
            source.stop()
    return digest, overflow
