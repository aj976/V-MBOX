"""Replay one frozen trace through one M6 budgeted strategy."""

import argparse
import platform
import subprocess
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from vmbox.collect.trace import read_trace
from vmbox.eval.harness import run_evaluation
from vmbox.eval.policies import PolicyStrategy
from vmbox.eval.result_reader import read_result, read_role_map
from vmbox.schema import ToolVersions


def reference_bytes(result_path: Path, trace_path: Path, labels_path: Path,
                    role_map_path: Path | None = None,
                    expected_role: str | None = None) -> int:
    roles = read_role_map(role_map_path)[0] if role_map_path is not None else None
    reference = read_result(result_path, legacy_roles=roles).result
    if expected_role is not None and reference.set_role != expected_role:
        raise ValueError("reference set_role differs from the budgeted run")
    trace_hash = "sha256:" + sha256(trace_path.read_bytes()).hexdigest()
    label_hash = "sha256:" + sha256(labels_path.read_bytes()).hexdigest()
    if reference.strategy != "unbounded" or reference.bytes_retained is None:
        raise ValueError("reference must be a measured unbounded result")
    if reference.trace_hash != trace_hash or reference.label_hash != label_hash:
        raise ValueError("reference trace/label hashes do not match this run")
    return reference.bytes_retained


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--full-result", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--strategy", choices=("fifo_ring", "fixed", "priority",
                                               "context_aware"), required=True)
    parser.add_argument("--budget-bytes", type=int, required=True)
    parser.add_argument("--journal-bytes", type=int, required=True)
    parser.add_argument("--segment-events", type=int, default=128)
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--sysmon-version", required=True)
    parser.add_argument("--set-role", choices=("tuning", "held_out"), required=True)
    parser.add_argument("--legacy-role-map", type=Path,
                        help="required when --full-result is a legacy v1 result")
    args = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("M6 live-trace evaluation requires the Windows VM")
    if args.budget_bytes < args.journal_bytes or args.journal_bytes <= 0:
        parser.error("budget must include a positive journal allocation")
    lockfile_bytes = args.lockfile.read_bytes()
    if not lockfile_bytes:
        parser.error("lockfile is empty")
    full_bytes = reference_bytes(args.full_result, args.trace, args.labels,
                                 args.legacy_role_map, args.set_role)
    header, _ = read_trace(args.trace)
    etw_version = None
    if any(source.startswith("etw") for source in header.sources):
        try:
            etw_version = version("pywintrace")
        except PackageNotFoundError:
            parser.error("ETW trace requires installed pywintrace version provenance")
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                     text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root,
                                         text=True).strip())
    versions = ToolVersions(
        python=platform.python_version(), vmbox=version("vmbox"),
        lockfile_hash="sha256:" + sha256(lockfile_bytes).hexdigest(),
        windows_build=platform.version(), sysmon_version=args.sysmon_version,
        etw_pywintrace=etw_version,
    )
    result = run_evaluation(
        args.trace, args.labels, args.out,
        strategy=PolicyStrategy(args.strategy, segment_events=args.segment_events),
        journal_bytes=args.journal_bytes, budget_bytes=args.budget_bytes,
        unbounded_bytes_retained=full_bytes, git_commit=commit, git_dirty=dirty,
        tool_versions=versions, set_role=args.set_role,
    )
    print("offline evaluation session, not forensic evidence")
    print(f"run_id: {result.run_id}")
    print(f"strategy: {result.strategy}")
    print(f"budget_bytes: {result.budget_bytes}")
    print(f"bytes_retained: {result.bytes_retained}")
    print(f"result: {args.out / 'result.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
