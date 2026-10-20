"""Create explicit M8 attempt and legacy-role manifests from selected runs."""

import argparse
from pathlib import Path

from vmbox.eval.inventory import write_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts-out", type=Path, required=True)
    parser.add_argument("--roles-out", type=Path, required=True)
    parser.add_argument("--set-role", choices=("tuning", "held_out"), required=True)
    parser.add_argument("--failed", action="append", default=[], metavar="RUN_ID=REASON")
    parser.add_argument("run_directories", nargs="*", type=Path)
    args = parser.parse_args()
    failed = {}
    for item in args.failed:
        if "=" not in item:
            parser.error("--failed must be RUN_ID=REASON")
        run_id, reason = item.split("=", 1)
        if not run_id or not reason:
            parser.error("--failed must be RUN_ID=REASON")
        failed[run_id] = reason
    write_inventory(args.run_directories, args.attempts_out, args.roles_out,
                    set_role=args.set_role, failed=failed)
    print(f"attempts: {args.attempts_out}")
    print(f"legacy_roles: {args.roles_out if args.roles_out.exists() else 'not needed'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
