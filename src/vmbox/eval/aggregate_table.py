"""Render M8 tables only from a validated results.json aggregate."""

import json
from pathlib import Path
from typing import Any

from vmbox.eval.aggregate_schema import AggregateResult


def _number(value: Any) -> str:
    if value is None:
        return "not measured"
    return f"{value:.6g}" if type(value) is float else str(value)


def _interval(value: Any) -> str:
    return "not measured" if value is None else f"[{_number(value[0])}, {_number(value[1])}]"


def render_tables(report_path: Path) -> str:
    """Reject raw result lists and any aggregate with a broken content hash."""
    report = AggregateResult.from_dict(json.loads(report_path.read_bytes()))
    lines = ["# M8 aggregate tables", "",
             f"Content hash: `{report.content_hash}`", "",
             f"Runs attempted: {report.runs_attempted}; completed: {report.runs_completed}; "
             f"failed: {report.runs_failed}.", "",
             "Independent unit: recorded trace. CIs are unadjusted bootstrap percentile "
             "intervals; run count is shown for each group.", "",
             "| Scenario | Role | Strategy | Budget bytes | n | Collection coverage "
             "mean [95% CI] | Evidence coverage mean [95% CI] |", "|---|---|---|---:|---:|---|---|"]
    for group in report.groups:
        budget = ("n/a (unbounded)" if group["strategy"] == "unbounded"
                  else str(group["budget_bytes"]))
        collection = group["metrics"]["collection_coverage"]
        evidence = group["metrics"]["evidence_coverage"]
        lines.append("| " + " | ".join((
            str(group["scenario_family"]), str(group["set_role"]), str(group["strategy"]),
            budget, str(collection["n"]),
            f"{_number(collection['mean'])} {_interval(collection['ci_95'])}",
            f"{_number(evidence['mean'])} {_interval(evidence['ci_95'])}",
        )) + " |")
    lines.extend(("", "| Scenario | Role | Comparison | Budget bytes | Metric | n | "
                  "Paired difference | 95% CI | Verdict | Reason |",
                  "|---|---|---|---:|---|---:|---:|---|---|---|"))
    for comparison in report.comparisons:
        lines.append("| " + " | ".join((
            str(comparison["scenario_family"]), str(comparison["set_role"]),
            f"{comparison['strategy_a']} - {comparison['strategy_b']}",
            ("n/a (unbounded)" if comparison["budget_bytes"] is None
             else str(comparison["budget_bytes"])), str(comparison["metric"]),
            str(comparison["n"]), _number(comparison["mean_paired_difference"]),
            _interval(comparison["ci_95"]), str(comparison["verdict"]),
            str(comparison["reason"] or comparison["ci_reason"] or "measured"),
        )) + " |")
    lines.extend(("", "Failed runs:"))
    if report.failed_runs:
        lines.extend(f"- `{item['run_id']}`: {item['reason']}" for item in report.failed_runs)
    else:
        lines.append("- None recorded.")
    lines.extend(("", "Limitations:"))
    lines.extend(f"- {item}" for item in report.limitations)
    return "\n".join(lines) + "\n"
