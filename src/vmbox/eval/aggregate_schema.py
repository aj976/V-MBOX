"""Validated derived M8 aggregate format; evidence schema remains version 1."""

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from vmbox.canonical import canonical_json
from vmbox.schema import SchemaModel

_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ROLES = {"tuning", "held_out"}
_METRIC_FIELDS = {"mean", "ci_95", "n", "reason", "ci_reason"}


@dataclass(frozen=True)
class AggregateResult(SchemaModel):
    aggregate_format_version: int
    generated_at: int
    unit_of_analysis: str
    ci_method: dict[str, Any]
    attempts_file_hash: str
    legacy_role_map_hash: str | None
    inputs: list[dict[str, str]]
    run_ids: list[str]
    runs_attempted: int
    runs_completed: int
    runs_failed: int
    failed_runs: list[dict[str, str]]
    groups: list[dict[str, Any]]
    comparisons: list[dict[str, Any]]
    limitations: list[str]
    content_hash: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.aggregate_format_version != 1 or self.generated_at < 0:
            raise ValueError("invalid aggregate format or timestamp")
        if self.unit_of_analysis != "independent_trace":
            raise ValueError("aggregate unit must be independent_trace")
        for digest in (self.attempts_file_hash, self.content_hash):
            if _HASH.fullmatch(digest) is None:
                raise ValueError("invalid aggregate hash")
        if self.legacy_role_map_hash is not None and _HASH.fullmatch(
            self.legacy_role_map_hash
        ) is None:
            raise ValueError("invalid legacy role mapping hash")
        if set(self.ci_method) != {"name", "seed", "resamples", "minimum_runs",
                                   "comparison_count", "unadjusted"} \
                or self.ci_method["name"] != "bootstrap_percentile" \
                or type(self.ci_method["seed"]) is not int \
                or type(self.ci_method["resamples"]) is not int \
                or self.ci_method["resamples"] < 100 \
                or type(self.ci_method["minimum_runs"]) is not int \
                or self.ci_method["minimum_runs"] < 2 \
                or self.ci_method["comparison_count"] != len(self.comparisons) \
                or self.ci_method["unadjusted"] is not True:
            raise ValueError("invalid CI method record")
        if self.runs_attempted != self.runs_completed + self.runs_failed \
                or self.runs_completed != len(self.inputs) \
                or self.runs_failed != len(self.failed_runs) \
                or self.run_ids != sorted(self.run_ids) \
                or len(set(self.run_ids)) != len(self.run_ids) \
                or len(self.run_ids) != self.runs_completed:
            raise ValueError("aggregate run accounting mismatch")
        if not self.limitations:
            raise ValueError("aggregate needs limitations")
        for entry in self.inputs:
            if type(entry) is not dict or set(entry) != {"run_id", "path", "sha256"} \
                    or _HASH.fullmatch(entry["sha256"]) is None:
                raise ValueError("invalid aggregate input")
        for failure in self.failed_runs:
            if type(failure) is not dict or set(failure) != {"run_id", "reason"} \
                    or not failure["run_id"] or not failure["reason"]:
                raise ValueError("invalid failed run")
        if {item["run_id"] for item in self.inputs} != set(self.run_ids) \
                or set(self.run_ids) & {item["run_id"] for item in self.failed_runs}:
            raise ValueError("aggregate input IDs disagree")
        for group in self.groups:
            if set(group) != {"scenario_family", "set_role", "strategy", "budget_bytes",
                              "strategy_rules_version", "trace_hashes", "label_hashes",
                              "config_hash", "tool_versions", "metrics", "run_ids"} \
                    or group["set_role"] not in _ROLES \
                    or group["trace_hashes"] != sorted(group["trace_hashes"]) \
                    or group["run_ids"] != sorted(group["run_ids"]):
                raise ValueError("invalid aggregate group")
            for summary in group["metrics"].values():
                if set(summary) != _METRIC_FIELDS or summary["n"] != len(group["run_ids"]):
                    raise ValueError("invalid metric summary")
                if summary["ci_95"] is None and summary["ci_reason"] is None:
                    raise ValueError("null CI requires a reason")
                if summary["n"] < self.ci_method["minimum_runs"] and summary["ci_reason"] \
                        != "insufficient_runs":
                    raise ValueError("small group CI must say insufficient_runs")
        for comparison in self.comparisons:
            if set(comparison) != {"scenario_family", "set_role", "strategy_a",
                                   "strategy_b", "budget_bytes", "metric", "n",
                                   "mean_paired_difference", "ci_95", "reason",
                                   "ci_reason", "verdict"} \
                    or comparison["set_role"] not in _ROLES \
                    or comparison["verdict"] not in {"difference_resolved", "inconclusive"}:
                raise ValueError("invalid comparison")
            interval = comparison["ci_95"]
            expected = ("difference_resolved" if interval is not None and
                        (interval[0] > 0 or interval[1] < 0) else "inconclusive")
            if comparison["verdict"] != expected:
                raise ValueError("comparison verdict disagrees with CI")
            if comparison["n"] < self.ci_method["minimum_runs"] and \
                    comparison["ci_reason"] != "insufficient_runs":
                raise ValueError("small paired CI must say insufficient_runs")
        content = {key: value for key, value in self.to_dict().items()
                   if key not in {"generated_at", "content_hash"}}
        if self.content_hash != "sha256:" + sha256(canonical_json(content)).hexdigest():
            raise ValueError("aggregate content hash mismatch")
