"""Synthetic M8 calculations are hand-checkable, not VM measurements."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from test_result_reader import _legacy

from vmbox.canonical import canonical_json
from vmbox.eval.aggregate import build_aggregate
from vmbox.eval.aggregate_schema import AggregateResult
from vmbox.eval.aggregate_table import render_tables


def _write_inputs(tmp_path: Path, *, legacy: bool = False) -> tuple[Path, Path | None]:
    template = _legacy()
    attempts = []
    roles = {}
    for trace_index in (1, 2):
        for strategy in ("unbounded", "fifo_ring", "priority"):
            data = deepcopy(template)
            run_id = f"{strategy}-{trace_index}"
            data.update(run_id=run_id, scenario_id="family_a", seed=trace_index,
                        trace_hash="sha256:" + str(trace_index) * 64,
                        label_hash="sha256:" + str(trace_index + 2) * 64,
                        strategy=strategy,
                        strategy_rules_version=("unbounded-v1" if strategy == "unbounded"
                                                else "m6-general-v2"),
                        budget_bytes=None if strategy == "unbounded" else 100,
                        budget_fraction_of_full=(None if strategy == "unbounded" else 0.5),
                        bytes_retained=200 if strategy == "unbounded" else 80)
            score = {"unbounded": 1.0, "fifo_ring": (0.5, 0.7)[trace_index - 1],
                     "priority": (0.8, 0.9)[trace_index - 1]}[strategy]
            data["metrics"]["collection_coverage"] = 1.0
            data["metrics"]["evidence_coverage"] = score
            if not legacy:
                data.update(result_format_version=2, set_role="tuning")
            else:
                roles[run_id] = "tuning"
            path = tmp_path / f"{run_id}.json"
            path.write_bytes(canonical_json(data))
            attempts.append({"run_id": run_id, "result_path": path.name,
                             "failure_reason": None})
    attempts.append({"run_id": "failed-extra", "result_path": None,
                     "failure_reason": "synthetic interrupted attempt"})
    attempts_path = tmp_path / "attempts.json"
    attempts_path.write_bytes(canonical_json({"attempts": attempts}))
    role_path = tmp_path / "roles.json" if legacy else None
    if role_path is not None:
        role_path.write_bytes(canonical_json(roles))
    return attempts_path, role_path


def _change(tmp_path: Path, filename: str, update) -> None:
    path = tmp_path / filename
    data = json.loads(path.read_bytes())
    update(data)
    path.write_bytes(canonical_json(data))


def test_paired_difference_and_failed_accounting(tmp_path: Path) -> None:
    attempts, _ = _write_inputs(tmp_path)
    aggregate = build_aggregate(attempts, minimum_runs=2, resamples=500,
                                generated_at=1)
    assert aggregate.runs_attempted == 7
    assert aggregate.runs_completed == 6 and aggregate.runs_failed == 1
    assert aggregate.failed_runs == [{"run_id": "failed-extra",
                                      "reason": "synthetic interrupted attempt"}]
    pair = next(item for item in aggregate.comparisons
                if item["scenario_family"] == "family_a" and
                {item["strategy_a"], item["strategy_b"]} == {"priority", "fifo_ring"} and
                item["metric"] == "evidence_coverage")
    assert abs(pair["mean_paired_difference"]) == pytest.approx(0.25)
    assert pair["ci_95"][0] > 0 or pair["ci_95"][1] < 0
    assert pair["verdict"] == "difference_resolved"
    assert aggregate.ci_method["comparison_count"] == len(aggregate.comparisons)


def test_default_minimum_suppresses_ci_and_inconclusive_verdict(tmp_path: Path) -> None:
    attempts, _ = _write_inputs(tmp_path)
    aggregate = build_aggregate(attempts, generated_at=1)
    group = next(item for item in aggregate.groups if item["scenario_family"] == "family_a"
                 and item["strategy"] == "priority")
    assert group["metrics"]["evidence_coverage"]["n"] == 2
    assert group["metrics"]["evidence_coverage"]["ci_95"] is None
    assert group["metrics"]["evidence_coverage"]["reason"] == "insufficient_runs"
    assert all(item["verdict"] == "inconclusive" for item in aggregate.comparisons)
    path = tmp_path / "results.json"
    path.write_bytes(aggregate.to_json())
    table = render_tables(path)
    assert "not measured" in table
    assert "inconclusive" in table
    assert "n/a (unbounded)" in table
    path.write_bytes(b"{}")
    with pytest.raises(ValueError):
        render_tables(path)


def test_ci_spanning_zero_is_inconclusive(tmp_path: Path) -> None:
    attempts, _ = _write_inputs(tmp_path)
    _change(tmp_path, "priority-1.json",
            lambda data: data["metrics"].update(evidence_coverage=0.4))
    _change(tmp_path, "priority-2.json",
            lambda data: data["metrics"].update(evidence_coverage=0.8))
    aggregate = build_aggregate(attempts, minimum_runs=2, resamples=500,
                                generated_at=1)
    pair = next(item for item in aggregate.comparisons
                if item["scenario_family"] == "family_a" and
                {item["strategy_a"], item["strategy_b"]} == {"priority", "fifo_ring"}
                and item["metric"] == "evidence_coverage")
    assert pair["ci_95"][0] <= 0 <= pair["ci_95"][1]
    assert pair["verdict"] == "inconclusive"


def test_regeneration_hash_is_independent_of_time(tmp_path: Path) -> None:
    attempts, _ = _write_inputs(tmp_path)
    first = build_aggregate(attempts, generated_at=1)
    second = build_aggregate(attempts, generated_at=2)
    assert first.content_hash == second.content_hash
    assert first.to_json() != second.to_json()
    assert AggregateResult.from_dict(json.loads(first.to_json())) == first


@pytest.mark.parametrize("field,expected", [
    ("config_hash", "config_hash mismatch"),
    ("strategy_rules_version", "strategy_rules_version mismatch"),
    ("tool_versions", "tool_versions mismatch"),
    ("trace_hash", "trace_hash set mismatch"),
    ("label_hash", "label_hash mismatch"),
    ("budget_bytes", "budget coverage mismatch"),
])
def test_group_mismatch_is_rejected(tmp_path: Path, field: str, expected: str) -> None:
    attempts, _ = _write_inputs(tmp_path)

    def mutate(data: dict) -> None:
        if field == "tool_versions":
            data[field]["python"] = "other"
        elif field == "budget_bytes":
            data[field] = 101
        elif field == "trace_hash":
            data[field] = "sha256:" + "9" * 64
        elif field == "label_hash":
            data[field] = "sha256:" + "9" * 64
        elif field == "config_hash":
            data[field] = "sha256:" + "9" * 64
        else:
            data[field] = "different"

    _change(tmp_path, "priority-2.json", mutate)
    with pytest.raises(ValueError, match=expected):
        build_aggregate(attempts, generated_at=1)


def test_roles_never_pool_and_legacy_mapping_hash_is_recorded(tmp_path: Path) -> None:
    attempts, roles = _write_inputs(tmp_path, legacy=True)
    with pytest.raises(ValueError, match="explicit set_role mapping"):
        build_aggregate(attempts, generated_at=1)
    assert roles is not None
    aggregate = build_aggregate(attempts, role_map_path=roles, generated_at=1)
    assert aggregate.legacy_role_map_hash is not None
    assert {group["set_role"] for group in aggregate.groups} == {"tuning"}
    mapping = json.loads(roles.read_bytes())
    mapping["priority-2"] = "held_out"
    roles.write_bytes(canonical_json(mapping))
    with pytest.raises(ValueError, match="tuning and held_out"):
        build_aggregate(attempts, role_map_path=roles, generated_at=1)


def test_distinct_held_out_traces_have_separate_pooled_group(tmp_path: Path) -> None:
    attempts_path, _ = _write_inputs(tmp_path)
    manifest = json.loads(attempts_path.read_bytes())
    for item in list(manifest["attempts"]):
        if item["result_path"] is None:
            continue
        original = json.loads((tmp_path / item["result_path"]).read_bytes())
        copied = deepcopy(original)
        copied["run_id"] = original["run_id"] + "-held"
        copied["set_role"] = "held_out"
        copied["trace_hash"] = "sha256:" + (
            "7" if original["seed"] == 1 else "8") * 64
        copied["label_hash"] = "sha256:" + (
            "9" if original["seed"] == 1 else "a") * 64
        copied["scenario_id"] = "family_b"
        path = tmp_path / (copied["run_id"] + ".json")
        path.write_bytes(canonical_json(copied))
        manifest["attempts"].append({"run_id": copied["run_id"],
                                     "result_path": path.name, "failure_reason": None})
    attempts_path.write_bytes(canonical_json(manifest))
    aggregate = build_aggregate(attempts_path, minimum_runs=2, generated_at=1)
    pooled = [group for group in aggregate.groups if group["scenario_family"] == "pooled"]
    assert {group["set_role"] for group in pooled} == {"tuning", "held_out"}
    assert all(len(group["trace_hashes"]) == 2 for group in pooled)
