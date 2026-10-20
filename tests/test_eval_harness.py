"""M5 strategy harness tests use synthetic events and are not measurements."""

from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

import pytest

from vmbox.collect.source import RawEvent
from vmbox.collect.trace import TraceHeader, write_trace
from vmbox.eval.harness import run_evaluation
from vmbox.eval.labels import freeze_labels
from vmbox.eval.strategy import SelectionOutcome, StrategyName
from vmbox.schema import Event, GroundTruthLabel, ToolVersions
from vmbox.store.segment import SelectionStats

HASH = "sha256:" + "0" * 64


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    header = TraceHeader(1, str(uuid4()), str(uuid4()), "boot", ["sysmon"], "test",
                         HASH, HASH, {"windows_build": "synthetic"}, False)
    trace = tmp_path / "trace.jsonl"
    ticks = iter([100, 101, 102])
    write_trace(trace, header, [
        RawEvent("sysmon", "PROC_START", {"Image": "C:/vmbox_anchor_n123.exe",
                                          "ProcessId": "10", "ParentProcessId": "1"}),
        RawEvent("sysmon", "PROC_START", {"Image": "C:/child.exe",
                                          "ProcessId": "11", "ParentProcessId": "10"}),
        RawEvent("sysmon", "PROC_EXIT", {"Image": "C:/child.exe",
                                         "ProcessId": "11", "ParentProcessId": "10"}),
    ], receipt_clock=lambda: next(ticks))
    labels = GroundTruthLabel.from_dict({
        "scenario_id": "synthetic", "run_id": str(uuid4()), "seed": 7,
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
    return trace, labels_path


@dataclass
class SyntheticDummy:
    """Test plumbing only; this is not the M6 fixed-policy implementation."""

    name: StrategyName = "fixed"
    rules_version: str = "synthetic-dummy-v1"
    received: tuple[Event, ...] | None = None
    allowance: int | None = None

    def select(self, events: tuple[Event, ...], sealed_bytes_budget: int | None,
               ) -> SelectionOutcome:
        self.received = events
        self.allowance = sealed_bytes_budget
        kept = (events[1],)
        return SelectionOutcome(kept, SelectionStats(
            seen=len(events), kept=1, dropped_by_policy=len(events) - 1,
            by_type={kept[0].event_type: 1}, promoted_by_context=0,
        ))


def _versions() -> ToolVersions:
    return ToolVersions("test", "test", HASH, "synthetic", "synthetic", None)


def test_dummy_runs_end_to_end_without_receiving_labels(tmp_path: Path):
    trace, labels = _inputs(tmp_path)
    strategy = SyntheticDummy()
    result = run_evaluation(
        trace, labels, tmp_path / "run", strategy=strategy, journal_bytes=2048,
        budget_bytes=8192, unbounded_bytes_retained=16384,
        git_commit="a" * 40, git_dirty=False, tool_versions=_versions(),
    )
    assert strategy.received is not None
    assert all(type(item) is Event for item in strategy.received)
    assert strategy.allowance == 6144
    assert result.strategy == "fixed"
    assert result.strategy_rules_version == "synthetic-dummy-v1"
    assert result.budget_fraction_of_full == 0.5
    assert result.metrics.collection_coverage == 1
    assert result.metrics.evidence_coverage == 1
    assert result.metrics.event_loss_rate == 0


def test_harness_rejects_strategy_output_not_from_stream(tmp_path: Path):
    trace, labels = _inputs(tmp_path)

    class ForgingDummy(SyntheticDummy):
        def select(self, events: tuple[Event, ...], sealed_bytes_budget: int | None,
                   ) -> SelectionOutcome:
            original = super().select(events, sealed_bytes_budget)
            forged = replace(original.events[0], priority=1)
            return SelectionOutcome((forged,), original.stats)

    with pytest.raises(ValueError, match="outside the normalized stream"):
        run_evaluation(
            trace, labels, tmp_path / "bad", strategy=ForgingDummy(), journal_bytes=2048,
            budget_bytes=8192, unbounded_bytes_retained=16384,
            git_commit="a" * 40, git_dirty=False, tool_versions=_versions(),
        )
    assert not (tmp_path / "bad").exists()
