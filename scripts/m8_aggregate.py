"""Regenerate validated M8 results.json and its tables from archived inputs."""

import argparse
import os
from pathlib import Path

from vmbox.eval.aggregate import build_aggregate
from vmbox.eval.aggregate_table import render_tables


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=Path, required=True)
    parser.add_argument("--legacy-role-map", type=Path)
    parser.add_argument("--out", type=Path, required=True,
                        help="new write-once results.json path")
    parser.add_argument("--table-out", type=Path, required=True,
                        help="new write-once Markdown table path")
    parser.add_argument("--minimum-runs", type=int, default=10)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--resamples", type=int, default=2000)
    args = parser.parse_args()
    if args.out.exists() or args.table_out.exists():
        parser.error("aggregate outputs are write-once; choose new paths")
    report = build_aggregate(args.attempts, role_map_path=args.legacy_role_map,
                             minimum_runs=args.minimum_runs, seed=args.seed,
                             resamples=args.resamples)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("xb") as stream:
        stream.write(report.to_json())
        stream.flush()
        os.fsync(stream.fileno())
    table = render_tables(args.out)
    args.table_out.parent.mkdir(parents=True, exist_ok=True)
    with args.table_out.open("x", encoding="utf-8") as stream:
        stream.write(table)
        stream.flush()
        os.fsync(stream.fileno())
    print(f"results: {args.out}")
    print(f"tables: {args.table_out}")
    print(f"content_hash: {report.content_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
