"""Run a write-once offline replay matrix for one frozen Windows VM trace."""

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from vmbox.eval.inventory import write_inventory
from vmbox.eval.matrix import plan_matrix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--sysmon-version", required=True)
    parser.add_argument("--set-role", choices=("tuning", "held_out"), required=True)
    parser.add_argument("--journal-bytes", type=int, default=8388608)
    parser.add_argument("--segment-events", type=int, default=128)
    parser.add_argument("--budget-bytes", type=int, nargs="+", required=True)
    args = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("run the matrix on the Windows VM")
    root = Path(__file__).resolve().parents[1]
    jobs = plan_matrix(
        python=sys.executable, project_root=root, trace=args.trace.resolve(),
        labels=args.labels.resolve(), output_root=args.out.resolve(),
        lockfile=args.lockfile.resolve(), sysmon_version=args.sysmon_version,
        set_role=args.set_role, budgets=tuple(args.budget_bytes),
        journal_bytes=args.journal_bytes, segment_events=args.segment_events,
    )
    args.out.mkdir(parents=True, exist_ok=False)
    logs = args.out / "logs"
    logs.mkdir()
    completed: list[Path] = []
    failed: dict[str, str] = {}
    reference_failed = False
    for job in jobs:
        output = logs / f"{job.name}.txt"
        with output.open("xb") as stream:
            result = subprocess.run(job.command, cwd=root, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
            stream.flush()
            os.fsync(stream.fileno())
        if result.returncode:
            failed[str(uuid4())] = f"{job.name}: exit code {result.returncode}; see logs"
            print(f"failed: {job.name} exit={result.returncode} log={output}")
            if job.name == "unbounded":
                reference_failed = True
        else:
            directory = args.out / job.name
            if not (directory / "result.json").is_file():
                failed[str(uuid4())] = f"{job.name}: exited zero without result.json"
                print(f"failed: {job.name} missing result.json")
                if job.name == "unbounded":
                    reference_failed = True
            else:
                completed.append(directory)
                print(f"completed: {job.name} log={output}")
        if reference_failed:
            break
    write_inventory(completed, args.out / "attempts.json", args.out / "legacy_roles.json",
                    set_role=args.set_role, failed=failed)
    print(f"attempts: {args.out / 'attempts.json'}")
    print(f"completed_runs: {len(completed)}")
    print(f"failed_runs: {len(failed)}")
    return 3 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
