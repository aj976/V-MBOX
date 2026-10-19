import json
import re
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vmbox.canonical import canonical_json
from vmbox.collect.replay import ReplaySource
from vmbox.collect.source import RawEvent
from vmbox.collect.trace import TraceHeader, read_trace, write_trace
from vmbox.normalize.normalizer import Normalizer

HASH = "sha256:" + "0" * 64


def header(*, opt_in=False):
    return TraceHeader(1, str(uuid4()), str(uuid4()), "boot", ["sysmon"], "0.1.0",
                       HASH, HASH, {"windows_build": "test"}, opt_in)


def raw(command="hello"):
    return RawEvent("sysmon", "PROC_START", {
        "ProcessId": "2", "ParentProcessId": "1", "Image": "C:\\example.exe",
        "CommandLine": command, "UtcTime": "2026-01-01 00:00:00.000",
    })


def normalize_all(trace_header, records):
    normalizer = Normalizer(trace_header)
    return b"".join(normalizer.normalize(record).to_json() + b"\n" for record in records)


@given(st.lists(st.text(max_size=30), min_size=0, max_size=10))
def test_trace_roundtrip_and_byte_identical_replay(commands):
    with TemporaryDirectory() as directory:
        h = header()
        path = Path(directory) / "trace.jsonl"
        events = [raw(command) for command in commands]
        digest = write_trace(path, h, events, receipt_clock=lambda: 10)
        assert digest == "sha256:" + sha256(path.read_bytes()).hexdigest()
        recovered_header, records = read_trace(path)
        assert recovered_header == h
        assert all("CommandLine" not in record.payload for record in records)
        first = ReplaySource(h, records)
        second = ReplaySource(h, records)
        assert first.run_id != second.run_id
        assert normalize_all(h, list(first.records())) == normalize_all(h, list(second.records()))
        assert canonical_json(asdict(h)) + b"\n" == path.read_bytes().splitlines(keepends=True)[0]


def test_trace_missing_sidecar_tamper_and_no_overwrite(tmp_path: Path):
    h = header()
    path = tmp_path / "trace.jsonl"
    write_trace(path, h, [raw()], receipt_clock=lambda: 10)
    with pytest.raises(FileExistsError):
        write_trace(path, h, [], receipt_clock=lambda: 10)
    original = path.read_bytes()
    path.write_bytes(original + b"x")
    with pytest.raises(ValueError):
        read_trace(path)
    path.write_bytes(original)
    Path(str(path) + ".sha256").unlink()
    with pytest.raises(ValueError, match="incomplete"):
        read_trace(path)


def test_noncanonical_and_torn_lines_rejected_even_with_matching_digest(tmp_path: Path):
    h = header()
    path = tmp_path / "trace.jsonl"
    write_trace(path, h, [raw()], receipt_clock=lambda: 10)
    first, second = path.read_bytes().splitlines(keepends=True)
    for altered in (first + second.rstrip(b"\n"), first + b" " + second):
        path.write_bytes(altered)
        Path(str(path) + ".sha256").write_bytes(
            canonical_json({"sha256": "sha256:" + sha256(altered).hexdigest()}) + b"\n")
        with pytest.raises(ValueError):
            read_trace(path)


def test_raw_trace_schema_template_loads():
    schema = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    block = re.search(r"### Raw trace.*?```text\n(.*?)```", schema, re.DOTALL)
    assert block is not None
    header_line, record_line = block.group(1).splitlines()
    parsed_header = TraceHeader.from_dict(json.loads(header_line))
    assert parsed_header.trace_format_version == 1
    assert canonical_json(asdict(parsed_header)) == header_line.encode()
    from vmbox.collect.trace import TraceRecord
    record = TraceRecord.from_dict(json.loads(record_line))
    assert canonical_json(asdict(record)) == record_line.encode()


def test_opt_in_local_only(tmp_path: Path):
    h = header(opt_in=True)
    with pytest.raises(ValueError):
        write_trace(tmp_path / "trace.jsonl", h, [raw()])
    path = tmp_path / "trace.local.jsonl"
    write_trace(path, h, [raw()], receipt_clock=lambda: 10)
    _, records = read_trace(path)
    assert records[0].payload["CommandLine"] == "hello"


def test_partial_null_fields_and_unknown_type(tmp_path: Path):
    h = header()
    path = tmp_path / "trace.jsonl"
    write_trace(path, h, [RawEvent("sysmon", "PROC_START", {})], receipt_clock=lambda: 10)
    _, records = read_trace(path)
    event = Normalizer(h).normalize(records[0])
    assert event.capture.status == "partial"
    assert event.pid is None and event.ppid is None and event.process is None
    with pytest.raises(ValueError, match="unknown event type"):
        Normalizer(h).normalize(type(records[0])("sysmon", "UNMAPPED", 10, {}))
