"""Synthetic raw trace exercises review and label freeze end to end."""

from pathlib import Path
from uuid import uuid4

from vmbox.collect.source import RawEvent
from vmbox.collect.trace import TraceHeader, write_trace
from vmbox.eval.labels import read_labels
from vmbox.eval.workflow import freeze_reviewed_labels, prepare_match_review
from vmbox.schema import GroundTruthLabel

HASH = "sha256:" + "0" * 64


def test_verified_trace_to_review_to_frozen_labels(tmp_path: Path):
    nonce = "n123"
    labels = GroundTruthLabel.from_dict({
        "scenario_id": "synthetic", "run_id": str(uuid4()), "seed": 1,
        "anchor": {"nonce": nonce, "event_type": "PROC_START",
                   "image_regex": r".*vmbox_anchor_n123\.exe$"},
        "steps": [{"step_id": "s1", "description": "child", "relevance": "attack",
                   "match": {"event_type": "PROC_START", "image_regex": r".*child\.exe$",
                             "ts_window_ns": [0, 10],
                             "pid_lineage": {"step_id": "anchor", "relation": "child_of"}}}],
        "benign_workload": "none", "review_resolutions": [],
    })
    draft = tmp_path / "labels.draft.json"
    draft.write_bytes(labels.to_json())
    header = TraceHeader(1, str(uuid4()), str(uuid4()), "boot", ["sysmon"], "test",
                         HASH, HASH, {"windows_build": "synthetic"}, False)
    trace = tmp_path / "trace.jsonl"
    times = iter([100, 101])
    events = [RawEvent("sysmon", "PROC_START", {"Image": "C:/vmbox_anchor_n123.exe",
                                                "ProcessId": "10", "ParentProcessId": "1"}),
              RawEvent("sysmon", "PROC_START", {"Image": "C:/child.exe",
                                                "ProcessId": "11", "ParentProcessId": "10"})]
    write_trace(trace, header, events, receipt_clock=lambda: next(times))
    review_path = tmp_path / "match_review.json"
    first = prepare_match_review(trace, draft, review_path)
    assert first.review.ambiguous == []
    assert first.collection_misses == set()
    frozen_path = tmp_path / "labels.json"
    digest, second = freeze_reviewed_labels(trace, draft, review_path, frozen_path)
    assert first.matched == second.matched
    assert read_labels(frozen_path, digest) == labels
