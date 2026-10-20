"""Synthetic capture covers trace publication and explicit internal loss."""

from pathlib import Path

import pytest

from vmbox.collect.capture import capture_sysmon_trace
from vmbox.collect.source import EventSink, RawEvent
from vmbox.collect.trace import read_trace
from vmbox.normalize.normalizer import Normalizer


class FakeSysmon:
    name = "sysmon"

    def __init__(self) -> None:
        self.stopped = False

    def start(self, sink: EventSink) -> None:
        for pid in (1, 2):
            sink(RawEvent("sysmon", "PROC_START", {
                "ProcessId": str(pid), "ParentProcessId": "0",
                "Image": "C:/example.exe"}))

    def stop(self) -> None:
        self.stopped = True

    def events(self):
        return iter(())

    def loss_counters(self) -> dict[str, int | None]:
        return {"sysmon_upstream_lost": None}


def test_capture_records_gap_before_hashing_trace(tmp_path: Path):
    source = FakeSysmon()
    path = tmp_path / "trace.jsonl"
    digest, overflow = capture_sysmon_trace(
        path, source, duration_s=0.001, sysmon_config=b"config", boot_id="boot",
        windows_build="synthetic", queue_capacity=1, receipt_clock=lambda: 100,
    )
    assert source.stopped
    assert overflow == 1
    assert digest.startswith("sha256:")
    header, records = read_trace(path)
    assert [record.event_type for record in records] == ["PROC_START", "CAPTURE_GAP"]
    normalizer = Normalizer(header)
    events = [normalizer.normalize(record) for record in records]
    assert [event.seq for event in events] == [0, 1]
    assert events[1].data["approx_missed"] == 1


def test_source_stop_failure_leaves_trace_incomplete(tmp_path: Path):
    class FailingSource(FakeSysmon):
        def stop(self) -> None:
            self.stopped = True
            raise RuntimeError("subscription failed")

    path = tmp_path / "trace.jsonl"
    with pytest.raises(RuntimeError, match="subscription failed"):
        capture_sysmon_trace(path, FailingSource(), duration_s=0.001,
                             sysmon_config=b"config", boot_id="boot",
                             windows_build="synthetic", queue_capacity=4)
    assert path.exists()
    assert not Path(str(path) + ".sha256").exists()
    with pytest.raises(ValueError, match="incomplete"):
        read_trace(path)


def test_live_callback_and_replay_have_identical_normalized_bytes(tmp_path: Path):
    from vmbox.collect.capture import make_sysmon_header

    header = make_sysmon_header(b"config", "boot", "synthetic", 4)
    live = Normalizer(header)
    live_bytes: list[bytes] = []
    path = tmp_path / "trace.jsonl"
    capture_sysmon_trace(
        path, FakeSysmon(), duration_s=0.001, sysmon_config=b"config",
        boot_id="boot", windows_build="synthetic", queue_capacity=4,
        receipt_clock=lambda: 100, header=header, emit_lifecycle=True,
        on_record=lambda record: live_bytes.append(live.normalize(record).to_json()),
    )
    saved_header, records = read_trace(path)
    replay = Normalizer(saved_header)
    assert live_bytes == [replay.normalize(record).to_json() for record in records]
    assert [record.event_type for record in records] == [
        "COLLECTOR_START", "PROC_START", "PROC_START", "COLLECTOR_STOP"]
