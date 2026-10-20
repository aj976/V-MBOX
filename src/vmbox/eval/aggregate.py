"""M8 aggregation over independent traces with paired, unadjusted CIs."""

import json
import random
import statistics
import time
from collections import defaultdict
from hashlib import sha256
from itertools import combinations
from pathlib import Path
from typing import Any

from vmbox.canonical import canonical_json
from vmbox.eval.aggregate_schema import AggregateResult
from vmbox.eval.result_reader import LoadedResult, read_result, read_role_map
from vmbox.schema import EvaluationResultV2

_METRICS = (
    "collection_coverage", "evidence_coverage", "storage_efficiency",
    "event_loss_rate", "reconstruction_order", "relations_precision",
    "relations_recall", "persistence_p50_ms", "persistence_p95_ms",
    "crash_recovery_rate", "bytes_retained",
)
_TOOL_KEYS = ("python", "vmbox", "lockfile_hash", "windows_build", "sysmon_version")


def _value(result: EvaluationResultV2, metric: str) -> float | None:
    metrics = result.metrics
    fields: dict[str, float | int | None] = {
        "collection_coverage": metrics.collection_coverage,
        "evidence_coverage": metrics.evidence_coverage,
        "storage_efficiency": metrics.storage_efficiency,
        "event_loss_rate": metrics.event_loss_rate,
        "reconstruction_order": metrics.reconstruction_accuracy.order,
        "relations_precision": metrics.reconstruction_accuracy.relations_precision,
        "relations_recall": metrics.reconstruction_accuracy.relations_recall,
        "persistence_p50_ms": metrics.persistence_latency_ms.p50,
        "persistence_p95_ms": metrics.persistence_latency_ms.p95,
        "crash_recovery_rate": metrics.crash_recovery_rate,
        "bytes_retained": result.bytes_retained,
    }
    value = fields[metric]
    return float(value) if value is not None else None


def _ci(values: list[float], *, seed: int, resamples: int, minimum_runs: int
        ) -> list[float] | None:
    if len(values) < minimum_runs:
        return None
    rng = random.Random(seed)
    samples = sorted(statistics.mean(rng.choices(values, k=len(values)))
                     for _ in range(resamples))
    return [samples[int(0.025 * resamples)],
            samples[min(resamples - 1, int(0.975 * resamples))]]


def _summary(results: list[EvaluationResultV2], metric: str, *, seed: int,
             resamples: int, minimum_runs: int) -> dict[str, Any]:
    values = [_value(result, metric) for result in results]
    n = len(results)
    ci_shortfall = "insufficient_runs" if n < minimum_runs else None
    if all(value is None for value in values):
        return {"mean": None, "ci_95": None, "n": n, "reason": "not_measured",
                "ci_reason": ci_shortfall or "not_measured"}
    if any(value is None for value in values):
        return {"mean": None, "ci_95": None, "n": n, "reason": "partial_measurement",
                "ci_reason": ci_shortfall or "partial_measurement"}
    measured = [value for value in values if value is not None]
    interval = _ci(measured, seed=seed, resamples=resamples, minimum_runs=minimum_runs)
    return {"mean": statistics.mean(measured), "ci_95": interval, "n": n,
            "reason": "insufficient_runs" if interval is None else None,
            "ci_reason": ci_shortfall}


def _read_attempts(path: Path) -> tuple[list[dict[str, Any]], str]:
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid attempt manifest") from exc
    if type(data) is not dict or set(data) != {"attempts"} \
            or type(data["attempts"]) is not list or not data["attempts"] \
            or canonical_json(data) != raw:
        raise ValueError("attempt manifest must be nonempty canonical JSON")
    seen: set[str] = set()
    for item in data["attempts"]:
        if type(item) is not dict or set(item) != {
            "run_id", "result_path", "failure_reason"
        } or type(item["run_id"]) is not str or not item["run_id"] \
                or item["run_id"] in seen:
            raise ValueError("invalid or duplicate attempt run_id")
        seen.add(item["run_id"])
        result_path, reason = item["result_path"], item["failure_reason"]
        if (result_path is None) == (reason is None):
            raise ValueError("attempt needs either result_path or failure_reason")
        if result_path is not None:
            relative = Path(result_path)
            if type(result_path) is not str or relative.is_absolute() or ".." in relative.parts:
                raise ValueError("result_path must stay under attempt manifest directory")
        elif type(reason) is not str or not reason.strip():
            raise ValueError("failed attempt requires a reason")
    return data["attempts"], "sha256:" + sha256(raw).hexdigest()


def _tool_key(result: EvaluationResultV2) -> tuple[str, ...]:
    versions = result.tool_versions.to_dict()
    return tuple(versions[key] for key in _TOOL_KEYS)


def _group(results: list[EvaluationResultV2], scenario: str, role: str,
           strategy: str, budget: int | None, *, seed: int, resamples: int,
           minimum_runs: int) -> dict[str, Any]:
    first = results[0]
    for item in results[1:]:
        for field in ("config_hash", "strategy_rules_version"):
            if getattr(item, field) != getattr(first, field):
                raise ValueError(f"group {scenario}/{strategy}: {field} mismatch")
        if _tool_key(item) != _tool_key(first):
            raise ValueError(f"group {scenario}/{strategy}: tool_versions mismatch")
    traces = [item.trace_hash for item in results]
    if len(set(traces)) != len(traces):
        raise ValueError(f"group {scenario}/{strategy}: replayed trace is not independent")
    return {
        "scenario_family": scenario, "set_role": role, "strategy": strategy,
        "budget_bytes": budget, "strategy_rules_version": first.strategy_rules_version,
        "trace_hashes": sorted(traces),
        "label_hashes": {item.trace_hash: item.label_hash for item in results},
        "config_hash": first.config_hash,
        "tool_versions": {key: first.tool_versions.to_dict()[key] for key in _TOOL_KEYS},
        "run_ids": sorted(item.run_id for item in results),
        "metrics": {name: _summary(results, name, seed=seed, resamples=resamples,
                                   minimum_runs=minimum_runs) for name in _METRICS},
    }


def _comparison(first: dict[str, Any], second: dict[str, Any],
                by_run: dict[str, EvaluationResultV2], metric: str, *, seed: int,
                resamples: int, minimum_runs: int) -> dict[str, Any]:
    base = {"scenario_family": first["scenario_family"], "set_role": first["set_role"],
            "strategy_a": first["strategy"], "strategy_b": second["strategy"],
            "budget_bytes": first["budget_bytes"], "metric": metric}
    first_by_trace = {by_run[run_id].trace_hash: by_run[run_id]
                      for run_id in first["run_ids"]}
    second_by_trace = {by_run[run_id].trace_hash: by_run[run_id]
                       for run_id in second["run_ids"]}
    if set(first_by_trace) != set(second_by_trace):
        raise ValueError("paired comparison trace_hash set mismatch; no partial pooling")
    if first["config_hash"] != second["config_hash"]:
        raise ValueError("paired comparison config_hash mismatch")
    if first["tool_versions"] != second["tool_versions"]:
        raise ValueError("paired comparison tool_versions mismatch")
    if first["label_hashes"] != second["label_hashes"]:
        raise ValueError("paired comparison label_hash mismatch")
    differences = []
    for trace_hash in sorted(first_by_trace):
        left = _value(first_by_trace[trace_hash], metric)
        right = _value(second_by_trace[trace_hash], metric)
        if left is None or right is None:
            return {**base, "n": len(first_by_trace), "mean_paired_difference": None,
                    "ci_95": None, "reason": "not_measured",
                    "ci_reason": ("insufficient_runs" if len(first_by_trace) < minimum_runs
                                  else "not_measured"), "verdict": "inconclusive"}
        differences.append(left - right)
    interval = _ci(differences, seed=seed, resamples=resamples,
                   minimum_runs=minimum_runs)
    verdict = ("difference_resolved" if interval is not None and
               (interval[0] > 0 or interval[1] < 0) else "inconclusive")
    return {**base, "n": len(differences),
            "mean_paired_difference": statistics.mean(differences),
            "ci_95": interval,
            "reason": "insufficient_runs" if interval is None else None,
            "ci_reason": "insufficient_runs" if interval is None else None,
            "verdict": verdict}


def build_aggregate(attempts_path: Path, *, role_map_path: Path | None = None,
                    minimum_runs: int = 10, seed: int = 1, resamples: int = 2000,
                    generated_at: int | None = None) -> AggregateResult:
    """Do not drop failed attempts or duplicate deterministic replays."""
    if minimum_runs < 2 or resamples < 100 or seed < 0:
        raise ValueError("invalid CI configuration")
    attempts, attempts_hash = _read_attempts(attempts_path)
    roles, mapping_hash = (read_role_map(role_map_path) if role_map_path is not None
                           else (None, None))
    loaded: list[tuple[str, LoadedResult]] = []
    failures = []
    for attempt in attempts:
        if attempt["failure_reason"] is not None:
            failures.append({"run_id": attempt["run_id"],
                             "reason": attempt["failure_reason"]})
            continue
        relative = attempt["result_path"]
        loaded_result = read_result(attempts_path.parent / relative, legacy_roles=roles)
        if loaded_result.result.run_id != attempt["run_id"]:
            raise ValueError(f"attempt run_id disagrees with result: {relative}")
        loaded.append((relative, loaded_result))
    by_run = {item.result.run_id: item.result for _, item in loaded}
    label_by_trace: dict[str, str] = {}
    role_by_trace: dict[str, str] = {}
    for result in by_run.values():
        prior = label_by_trace.setdefault(result.trace_hash, result.label_hash)
        if prior != result.label_hash:
            raise ValueError("label_hash mismatch for the same trace_hash")
        prior_role = role_by_trace.setdefault(result.trace_hash, result.set_role)
        if prior_role != result.set_role:
            raise ValueError("tuning and held_out cannot share a trace")
    buckets: dict[tuple[str, str, str, int | None], list[EvaluationResultV2]] = defaultdict(list)
    for result in by_run.values():
        buckets[(result.scenario_id, result.set_role, result.strategy,
                 result.budget_bytes)].append(result)
    for role in ("tuning", "held_out"):
        selected = [result for result in by_run.values() if result.set_role == role]
        if selected:
            for result in selected:
                buckets[("pooled", role, result.strategy, result.budget_bytes)].append(result)
    groups = [_group(results, *key, seed=seed, resamples=resamples,
                     minimum_runs=minimum_runs)
              for key, results in sorted(buckets.items(), key=lambda item: str(item[0]))]
    coverage_by_strategy: dict[tuple[str, str, str], set[str]] = {}
    for group in groups:
        key = (group["scenario_family"], group["set_role"], group["strategy"])
        traces = set(group["trace_hashes"])
        if key in coverage_by_strategy and coverage_by_strategy[key] != traces:
            raise ValueError("budget coverage mismatch: strategy trace sets differ")
        coverage_by_strategy[key] = traces
    group_index = {(group["scenario_family"], group["set_role"], group["strategy"],
                    group["budget_bytes"]): group for group in groups}
    comparisons = []
    for group in groups:
        if group["strategy"] == "unbounded":
            continue
        scenario, role, _, budget = (group["scenario_family"], group["set_role"],
                                     group["strategy"], group["budget_bytes"])
        reference = group_index.get((scenario, role, "unbounded", None))
        if reference is None:
            raise ValueError(f"missing unbounded baseline for {scenario}/{role}")
        for metric in _METRICS:
            comparisons.append(_comparison(group, reference, by_run, metric,
                                           seed=seed, resamples=resamples,
                                           minimum_runs=minimum_runs))
    for (scenario, role, budget) in sorted({
        (group["scenario_family"], group["set_role"], group["budget_bytes"])
        for group in groups if group["strategy"] != "unbounded"
    }, key=str):
        peers = [group for group in groups if group["scenario_family"] == scenario and
                 group["set_role"] == role and group["budget_bytes"] == budget and
                 group["strategy"] != "unbounded"]
        if not any(peer["strategy"] == "fifo_ring" for peer in peers):
            raise ValueError(f"missing fifo_ring baseline for {scenario}/{role}/{budget}")
        for left, right in combinations(peers, 2):
            for metric in _METRICS:
                comparisons.append(_comparison(left, right, by_run, metric,
                                               seed=seed, resamples=resamples,
                                               minimum_runs=minimum_runs))
    content: dict[str, Any] = {
        "aggregate_format_version": 1,
        "unit_of_analysis": "independent_trace",
        "ci_method": {"name": "bootstrap_percentile", "seed": seed,
                      "resamples": resamples, "minimum_runs": minimum_runs,
                      "comparison_count": len(comparisons), "unadjusted": True},
        "attempts_file_hash": attempts_hash, "legacy_role_map_hash": mapping_hash,
        "inputs": sorted(({"run_id": loaded_result.result.run_id, "path": relative,
                           "sha256": loaded_result.file_hash}
                          for relative, loaded_result in loaded), key=lambda item: item["run_id"]),
        "run_ids": sorted(by_run), "runs_attempted": len(attempts),
        "runs_completed": len(loaded), "runs_failed": len(failures),
        "failed_runs": sorted(failures, key=lambda item: item["run_id"]),
        "groups": groups, "comparisons": comparisons,
        "limitations": [
            "Recorded traces are the independent unit; deterministic replays are not new runs.",
            "Confidence intervals are unadjusted for multiple comparisons.",
            "Offline replay measures local retention, not live crash recovery "
            "or source completeness.",
        ],
    }
    digest = "sha256:" + sha256(canonical_json(content)).hexdigest()
    return AggregateResult.from_dict({**content,
                                      "generated_at": time.time_ns() if generated_at is None
                                      else generated_at, "content_hash": digest})
