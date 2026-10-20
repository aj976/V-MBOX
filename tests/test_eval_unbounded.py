"""Offline reference uses actual M3 files; fixture numbers are synthetic."""

from pathlib import Path
from uuid import uuid4

import pytest

from vmbox.collect.source import RawEvent
from vmbox.collect.trace import TraceHeader, write_trace
from vmbox.eval.labels import freeze_labels
from vmbox.eval.unbounded import run_unbounded
from vmbox.integrity.chain import verify_chain
from vmbox.schema import GroundTruthLabel, ToolVersions
from vmbox.store.budget import retained_bytes
from vmbox.store.manifest import read_manifest

HASH = "sha256:" + "0" * 64


def test_unbounded_replay_measures_real_retained_bytes(tmp_path: Path):
    header = TraceHeader(1, str(uuid4()), str(uuid4()), "boot", ["sysmon"], "test",
                         HASH, HASH, {"windows_build": "synthetic"}, False)
    trace = tmp_path / "trace.jsonl"
    ticks = iter([100, 101])
    write_trace(trace, header, [
        RawEvent("sysmon", "PROC_START", {"Image": "C:/vmbox_anchor_n123.exe",
                                          "ProcessId": "10", "ParentProcessId": "1"}),
        RawEvent("sysmon", "PROC_START", {"Image": "C:/child.exe",
                                          "ProcessId": "11", "ParentProcessId": "10"}),
    ], receipt_clock=lambda: next(ticks))
    labels = GroundTruthLabel.from_dict({
        "scenario_id": "synthetic", "run_id": str(uuid4()), "seed": 1,
        "anchor": {"nonce": "n123", "event_type": "PROC_START",
                   "image_regex": r".*vmbox_anchor_n123\.exe$"},
        "steps": [{"step_id": "s1", "description": "child", "relevance": "attack",
                   "match": {"event_type": "PROC_START", "image_regex": r".*child\.exe$",
                             "ts_window_ns": [0, 10],
                             "pid_lineage": {"step_id": "anchor", "relation": "child_of"}}}],
        "benign_workload": "none", "review_resolutions": [],
    })
    labels_path = tmp_path / "labels.json"
    freeze_labels(labels_path, labels)
    versions = ToolVersions("test", "test", HASH, "synthetic", "synthetic", None)
    out = tmp_path / "run"
    result = run_unbounded(trace, labels_path, out, journal_bytes=2048,
                           git_commit="a" * 40, git_dirty=False,
                           strategy_rules_version="test", tool_versions=versions)
    manifest = read_manifest(out / "manifest.json")
    assert manifest.mode == "offline_eval" and manifest.anchor is None
    assert verify_chain(out, manifest).status == "ok"
    assert result.bytes_retained == retained_bytes(out)
    assert result.budget_bytes is None and result.budget_fraction_of_full is None
    assert result.metrics.collection_coverage == 1
    assert result.metrics.evidence_coverage == 1
    assert result.metrics.persistence_latency_ms.p50 is None
    assert (out / "result.json").read_bytes() == result.to_json()
    with pytest.raises(FileExistsError):
        run_unbounded(trace, labels_path, out, journal_bytes=2048,
                      git_commit="a" * 40, git_dirty=False,
                      strategy_rules_version="test", tool_versions=versions)
