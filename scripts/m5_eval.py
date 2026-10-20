"""Run the M5 offline unbounded reference on a frozen VM trace."""

import argparse
import platform
import subprocess
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from vmbox.collect.trace import read_trace
from vmbox.eval.unbounded import run_unbounded
from vmbox.schema import ToolVersions


def _git_provenance() -> tuple[str, bool]:
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                     text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root,
                                         text=True).strip())
    return commit, dirty


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--journal-bytes", type=int, required=True)
    parser.add_argument("--lockfile", type=Path, required=True,
                        help="frozen pip package snapshot from this VM run")
    parser.add_argument("--sysmon-version", required=True,
                        help="version reported by Sysmon on the VM")
    args = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("M5 live-trace evaluation requires the Windows VM")
    lockfile_bytes = args.lockfile.read_bytes()
    if not lockfile_bytes:
        parser.error("lockfile is empty")
    header, _ = read_trace(args.trace)
    etw_version = None
    if any(source.startswith("etw") for source in header.sources):
        try:
            etw_version = version("pywintrace")
        except PackageNotFoundError:
            parser.error("ETW trace requires installed pywintrace version provenance")
    commit, dirty = _git_provenance()
    versions = ToolVersions(
        python=platform.python_version(), vmbox=version("vmbox"),
        lockfile_hash="sha256:" + sha256(lockfile_bytes).hexdigest(),
        windows_build=platform.version(), sysmon_version=args.sysmon_version,
        etw_pywintrace=etw_version,
    )
    result = run_unbounded(
        args.trace, args.labels, args.out, journal_bytes=args.journal_bytes,
        git_commit=commit, git_dirty=dirty,
        strategy_rules_version="unbounded-v1", tool_versions=versions,
    )
    print("offline evaluation session, not forensic evidence")
    print(f"run_id: {result.run_id}")
    print(f"bytes_retained: {result.bytes_retained}")
    print("collection_coverage: " + (
        str(result.metrics.collection_coverage)
        if result.metrics.collection_coverage is not None else "not measured"
    ))
    print("evidence_coverage: " + (
        str(result.metrics.evidence_coverage)
        if result.metrics.evidence_coverage is not None else "not measured"
    ))
    print(f"result: {args.out / 'result.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
