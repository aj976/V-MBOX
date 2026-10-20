"""Compatibility wrapper for the M5 unbounded evaluation baseline."""

from pathlib import Path

from vmbox.eval.harness import run_evaluation
from vmbox.eval.strategy import UnboundedStrategy
from vmbox.schema import EvaluationResult, ToolVersions


def run_unbounded(trace_path: Path, labels_path: Path, output_dir: Path, *,
                  journal_bytes: int, git_commit: str, git_dirty: bool,
                  strategy_rules_version: str, tool_versions: ToolVersions) -> EvaluationResult:
    """Replay one frozen trace; caller supplies recorded provenance, never defaults."""
    return run_evaluation(
        trace_path, labels_path, output_dir, strategy=UnboundedStrategy(
            rules_version=strategy_rules_version), journal_bytes=journal_bytes,
        budget_bytes=None, unbounded_bytes_retained=None, git_commit=git_commit,
        git_dirty=git_dirty, tool_versions=tool_versions,
    )
