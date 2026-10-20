"""Synthetic selection checks; these are not VM measurements."""

from dataclasses import replace
from pathlib import Path

from test_eval_harness import _inputs, _versions

from vmbox.collect.trace import read_trace
from vmbox.eval.harness import run_evaluation
from vmbox.eval.policies import PolicyStrategy
from vmbox.eval.strategy import UnboundedStrategy
from vmbox.normalize.normalizer import Normalizer


def test_budgeted_strategies_share_four_total_budgets(tmp_path: Path) -> None:
    trace, labels = _inputs(tmp_path)
    full = run_evaluation(
        trace, labels, tmp_path / "full", strategy=UnboundedStrategy(),
        journal_bytes=2048, budget_bytes=None, unbounded_bytes_retained=None,
        git_commit="a" * 40, git_dirty=False, tool_versions=_versions(),
    )
    assert full.bytes_retained is not None
    budgets = (2048, 3072, 4096, full.bytes_retained)
    for name in ("fifo_ring", "fixed", "priority", "context_aware"):
        for budget in budgets:
            result = run_evaluation(
                trace, labels, tmp_path / f"{name}_{budget}",
                strategy=PolicyStrategy(name), journal_bytes=2048,
                budget_bytes=budget, unbounded_bytes_retained=full.bytes_retained,
                git_commit="a" * 40, git_dirty=False, tool_versions=_versions(),
            )
            assert result.bytes_retained is not None
            assert result.bytes_retained <= budget
            assert result.strategy_rules_version == "m6-general-v1"


def test_fifo_keeps_latest_event_when_one_fits(tmp_path: Path) -> None:
    trace, _ = _inputs(tmp_path)
    header, records = read_trace(trace)
    normalizer = Normalizer(header)
    events = tuple(normalizer.normalize(record) for record in records)
    selector = PolicyStrategy("fifo_ring")
    one_event_size = next(
        allowance for allowance in range(400, 2000)
        if len(selector.select(events, allowance).events) == 1
    )
    selected = selector.select(events, one_event_size)
    assert selected.events == (events[-1],)
    assert selected.stats.dropped_by_policy == 2


def test_fixed_policy_drops_unlisted_types(tmp_path: Path) -> None:
    trace, _ = _inputs(tmp_path)
    header, records = read_trace(trace)
    normalizer = Normalizer(header)
    events = tuple(normalizer.normalize(record) for record in records)
    image_load = replace(events[-1], event_type="MEM_IMAGE_LOAD", category="memory")
    selected = PolicyStrategy("fixed").select((*events[:-1], image_load), 10000)
    assert selected.events == events[:-1]
    assert selected.stats.dropped_by_policy == 1
    assert selected.stats.promoted_by_context == 0


def test_context_promotes_temporally_related_pid(tmp_path: Path) -> None:
    trace, _ = _inputs(tmp_path)
    header, records = read_trace(trace)
    normalizer = Normalizer(header)
    events = tuple(normalizer.normalize(record) for record in records)
    memory = replace(events[1], event_type="MEM_PROCESS_ACCESS", category="memory")
    network = replace(events[2], event_type="NET_CONNECT", category="network")
    selected = PolicyStrategy("context_aware").select((events[0], memory, network), 10000)
    assert selected.stats.promoted_by_context == 2
