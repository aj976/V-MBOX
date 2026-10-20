"""Matrix planning prevents missing baselines and unequal budgets."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import m8_matrix
from vmbox.eval.matrix import plan_matrix


def test_plan_has_unbounded_and_four_equal_budget_strategy_sets(tmp_path: Path) -> None:
    jobs = plan_matrix(
        python="python", project_root=tmp_path, trace=tmp_path / "trace.jsonl",
        labels=tmp_path / "labels.json", output_root=tmp_path / "runs",
        lockfile=tmp_path / "lock.txt", sysmon_version="test", set_role="held_out",
        budgets=(9_437_184, 10_485_760, 11_534_336, 12_582_912),
        journal_bytes=8_388_608, segment_events=128,
    )
    assert len(jobs) == 17
    assert jobs[0].name == "unbounded"
    assert all("--set-role" in job.command and "held_out" in job.command
               for job in jobs)
    by_strategy = {}
    for job in jobs[1:]:
        strategy = job.command[job.command.index("--strategy") + 1]
        budget = job.command[job.command.index("--budget-bytes") + 1]
        by_strategy.setdefault(strategy, set()).add(budget)
    assert len(by_strategy) == 4
    assert len({frozenset(budgets) for budgets in by_strategy.values()}) == 1


def test_matrix_rejects_duplicate_or_unfunded_budget(tmp_path: Path) -> None:
    common = dict(python="python", project_root=tmp_path, trace=tmp_path / "t",
                  labels=tmp_path / "l", output_root=tmp_path / "o",
                  lockfile=tmp_path / "k", sysmon_version="test", set_role="tuning",
                  journal_bytes=100, segment_events=128)
    with pytest.raises(ValueError):
        plan_matrix(**common, budgets=(200, 200))
    with pytest.raises(ValueError):
        plan_matrix(**common, budgets=(100,))


def test_failed_unbounded_reference_is_recorded_without_budgeted_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "matrix"
    monkeypatch.setattr(m8_matrix.platform, "system", lambda: "Windows")
    calls = []

    def fail_run(*args: object, **kwargs: object) -> SimpleNamespace:
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(m8_matrix.subprocess, "run", fail_run)
    monkeypatch.setattr(m8_matrix.sys, "argv", [
        "m8_matrix.py", "--trace", str(tmp_path / "trace"), "--labels",
        str(tmp_path / "labels"), "--out", str(output), "--lockfile",
        str(tmp_path / "lock"), "--sysmon-version", "test", "--set-role",
        "held_out", "--budget-bytes", "9437184",
    ])
    assert m8_matrix.main() == 3
    attempts = json.loads((output / "attempts.json").read_bytes())["attempts"]
    assert len(calls) == 1
    assert len(attempts) == 1
    assert attempts[0]["result_path"] is None
    assert "unbounded" in attempts[0]["failure_reason"]
