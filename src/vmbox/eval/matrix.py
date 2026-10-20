"""Plan one equal-budget replay matrix for one frozen independent trace."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

STRATEGIES = ("fifo_ring", "fixed", "priority", "context_aware")


@dataclass(frozen=True)
class MatrixJob:
    name: str
    command: tuple[str, ...]


def plan_matrix(*, python: str, project_root: Path, trace: Path,
                labels: Path, output_root: Path, lockfile: Path,
                sysmon_version: str, set_role: Literal["tuning", "held_out"],
                budgets: tuple[int, ...], journal_bytes: int,
                segment_events: int) -> tuple[MatrixJob, ...]:
    if (not python or not budgets or len(set(budgets)) != len(budgets)
            or any(value <= journal_bytes for value in budgets)
            or journal_bytes <= 0 or segment_events <= 0 or not sysmon_version):
        raise ValueError("invalid equal-budget matrix configuration")
    common = ("--trace", str(trace), "--labels", str(labels),
              "--journal-bytes", str(journal_bytes), "--lockfile", str(lockfile),
              "--sysmon-version", sysmon_version, "--set-role", set_role)
    jobs = [MatrixJob("unbounded", (python, str(project_root / "scripts" / "m5_eval.py"),
                                    *common, "--out", str(output_root / "unbounded")))]
    for strategy in STRATEGIES:
        for budget in budgets:
            name = f"{strategy}_{budget}"
            jobs.append(MatrixJob(name, (
                python, str(project_root / "scripts" / "m6_eval.py"), *common,
                "--full-result", str(output_root / "unbounded" / "result.json"),
                "--out", str(output_root / name), "--strategy", strategy,
                "--budget-bytes", str(budget),
                "--segment-events", str(segment_events),
            )))
    return tuple(jobs)
