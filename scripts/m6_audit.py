"""Audit sealed versus journal-only retention in existing M6 VM runs."""

import argparse
from pathlib import Path

from vmbox.eval.audit import audit_run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    args = parser.parse_args()
    directories = sorted(path for path in args.run_root.glob("m6_*")
                         if path.is_dir() and (path / "result.json").is_file())
    if not directories:
        parser.error("no complete m6_* result directories found")
    print("run\tstrategy\tbudget_bytes\tcollected\tsealed\tjournal_only\tmissing"
          "\tsealed_coverage\ttombstones\tjournal_evicted_frames")
    for directory in directories:
        item = audit_run(args.trace, args.labels, directory)
        coverage = "not measured" if item.sealed_coverage is None else str(item.sealed_coverage)
        print(f"{directory.name}\t{item.strategy}\t{item.budget_bytes}\t"
              f"{item.collected_steps}\t{item.sealed_steps}\t{item.journal_only_steps}\t"
              f"{item.missing_steps}\t{coverage}\t{item.tombstones}\t"
              f"{item.journal_evicted_frames}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
