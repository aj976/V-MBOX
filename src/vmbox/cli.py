"""V-MBOX command line. Commands are added as milestones become verified."""

import argparse
from pathlib import Path

from vmbox.anchor.receipt_crypto import load_public_key
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.receipts import verify_receipts
from vmbox.store.journal import recover_journal
from vmbox.store.manifest import read_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vmbox")
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify = subcommands.add_parser("verify", help="verify local chain and journal integrity")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--anchor-pubkey", type=Path)
    verify.add_argument("--anchor-receipts", type=Path,
                        help="directory containing an exported anchor receipts/ tree")
    args = parser.parse_args(argv)
    if args.command == "verify":
        if args.anchor_receipts is not None and args.anchor_pubkey is None:
            parser.error("--anchor-receipts requires --anchor-pubkey")
        try:
            manifest = read_manifest(args.evidence / "manifest.json")
        except FileNotFoundError:
            print("manifest: missing; evidence incomplete")
            return 3
        except ValueError:
            print("manifest: invalid")
            return 2
        chain = verify_chain(args.evidence, manifest)
        try:
            journal = recover_journal(args.evidence / "journal.bin")
            journal_reason = journal.incomplete_reason
        except FileNotFoundError:
            journal_reason = "journal missing"
        print(f"chain: {chain.status}; {chain.reason or 'local hash chain matches'}")
        anchor_status = None
        if args.anchor_pubkey is not None:
            try:
                public_key = load_public_key(args.anchor_pubkey)
                anchor_status = verify_receipts(manifest, chain, public_key, args.evidence,
                                                args.anchor_receipts)
                print(f"anchor: {anchor_status.status}; {anchor_status.reason}")
            except (OSError, ValueError) as exc:
                print(f"anchor: tampered; {exc}")
                return 2
        else:
            print("anchor: not checked")
        print(f"journal: {'incomplete' if journal_reason else 'readable, unverified'}")
        if journal_reason:
            print(f"journal reason: {journal_reason}")
        if chain.status == "tampered" or (anchor_status and anchor_status.status == "tampered"):
            return 2
        if chain.status == "incomplete" or journal_reason or (
            anchor_status and anchor_status.status == "incomplete"
        ):
            return 3
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
