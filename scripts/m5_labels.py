"""Review and freeze M5 labels against a verified raw trace."""

import argparse
from pathlib import Path

from vmbox.eval.matching import resolve_match_review
from vmbox.eval.workflow import freeze_reviewed_labels, prepare_match_review


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--trace", type=Path, required=True)
    prepare.add_argument("--draft", type=Path, required=True)
    prepare.add_argument("--review", type=Path, required=True)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--review", type=Path, required=True)
    resolve.add_argument("--step-id", required=True)
    resolve.add_argument("--event-id", required=True)
    resolve.add_argument("--reviewer", required=True)
    freeze = commands.add_parser("freeze")
    freeze.add_argument("--trace", type=Path, required=True)
    freeze.add_argument("--draft", type=Path, required=True)
    freeze.add_argument("--review", type=Path, required=True)
    freeze.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare_match_review(args.trace, args.draft, args.review)
        print(f"matched_steps: {len(result.matched)}")
        print(f"collection_misses: {len(result.collection_misses)}")
        print(f"ambiguous_steps: {len(result.review.ambiguous)}")
        print(f"blocked_steps: {len(result.blocked)}")
    elif args.command == "resolve":
        review = resolve_match_review(args.review, args.step_id, args.event_id,
                                      args.reviewer)
        print(f"reviewed_steps: {sum(item.resolution is not None for item in review.ambiguous)}")
    else:
        digest, result = freeze_reviewed_labels(args.trace, args.draft, args.review,
                                                args.out)
        print(f"label_hash: {digest}")
        print(f"matched_steps: {len(result.matched)}")
        print(f"collection_misses: {len(result.collection_misses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
