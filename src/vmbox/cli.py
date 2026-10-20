"""V-MBOX command line. Commands are added as milestones become verified."""

import argparse
from pathlib import Path

from vmbox.integrity.chain import verify_chain
from vmbox.reconstruct.build import build_reconstruction
from vmbox.recover.evidence import RecoveryResult, recover_evidence
from vmbox.store.journal import recover_journal
from vmbox.store.manifest import read_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vmbox")
    subcommands = parser.add_subparsers(dest="command", required=True)
    record = subcommands.add_parser("record", help="live recording (not yet implemented)")
    record.add_argument("--anchor-endpoint")
    record.add_argument("--anchor-pubkey", type=Path)
    verify = subcommands.add_parser("verify", help="verify local chain and journal integrity")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--anchor-pubkey", type=Path)
    verify.add_argument("--anchor-receipts", type=Path,
                        help="directory containing an exported anchor receipts/ tree")
    for name in ("recover", "timeline"):
        command = subcommands.add_parser(name, help=f"{name} surviving evidence")
        command.add_argument("--evidence", type=Path, required=True)
        command.add_argument("--anchor-pubkey", type=Path)
        command.add_argument("--anchor-receipts", type=Path)
        if name == "timeline":
            command.add_argument("--pid", type=int)
            command.add_argument("--since", type=int, help="inclusive UTC nanoseconds")
            command.add_argument("--until", type=int, help="inclusive UTC nanoseconds")
    report = subcommands.add_parser("report", help="write JSON and HTML reports")
    report.add_argument("--evidence", type=Path, required=True)
    report.add_argument("--out", type=Path, required=True)
    report.add_argument("--anchor-pubkey", type=Path)
    report.add_argument("--anchor-receipts", type=Path)
    args = parser.parse_args(argv)
    if args.command == "record":
        if not args.anchor_endpoint or args.anchor_pubkey is None:
            parser.error("live record requires --anchor-endpoint and --anchor-pubkey")
        parser.error("live recording is not implemented; unverified until run on Windows VM")
    if args.command == "report":
        from vmbox.reconstruct.report import build_report, write_report

        if args.anchor_receipts is not None and args.anchor_pubkey is None:
            parser.error("--anchor-receipts requires --anchor-pubkey")
        try:
            recovered = recover_evidence(args.evidence, anchor_public_key=args.anchor_pubkey,
                                         anchor_receipts=args.anchor_receipts)
            built = build_report(args.evidence, recovered,
                                 anchor_public_key=args.anchor_pubkey,
                                 anchor_receipts=args.anchor_receipts)
            paths = write_report(args.out, built)
        except FileNotFoundError as exc:
            print(f"evidence incomplete: missing {exc.filename}")
            return 3
        except (OSError, ValueError) as exc:
            print(f"report failed: {exc}")
            return 2
        print(f"report_json: {paths[0]}")
        print(f"report_html: {paths[1]}")
        print(f"content_hash: {built.content_hash}")
        return 2 if recovered.status == "tampered" else 3 if recovered.status == "incomplete" else 0
    if args.command in {"recover", "timeline"}:
        if args.anchor_receipts is not None and args.anchor_pubkey is None:
            parser.error("--anchor-receipts requires --anchor-pubkey")
        if args.command == "timeline" and args.since is not None and args.until is not None \
                and args.since > args.until:
            parser.error("--since must not exceed --until")
        try:
            recovered = recover_evidence(args.evidence, anchor_public_key=args.anchor_pubkey,
                                         anchor_receipts=args.anchor_receipts)
        except FileNotFoundError as exc:
            print(f"evidence incomplete: missing {exc.filename}")
            return 3
        except (OSError, ValueError) as exc:
            print(f"evidence invalid: {exc}")
            return 2
        _print_recovery(recovered)
        if args.command == "timeline":
            for item in recovered.events:
                event = item.event
                if args.pid is not None and event.pid != args.pid:
                    continue
                if args.since is not None and event.ts_ns < args.since:
                    continue
                if args.until is not None and event.ts_ns > args.until:
                    continue
                pid = event.pid if event.pid is not None else "unknown"
                print(f"seq={event.seq} ts_ns={event.ts_ns} pid={pid} "
                      f"type={event.event_type} integrity={item.integrity} "
                      f"event_id={event.event_id}")
            for limitation in build_reconstruction(recovered).limitations:
                print(f"limitation: {limitation}")
        return 2 if recovered.status == "tampered" else 3 if recovered.status == "incomplete" else 0
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
        if manifest.mode == "offline_eval":
            print("offline evaluation session, not forensic evidence")
            print(f"integrity level: {'chained' if chain.status == 'ok' else chain.status}")
            print("receipt status: not applicable to offline evaluation")
        elif args.anchor_pubkey is not None:
            try:
                from vmbox.anchor.receipt_crypto import load_public_key
                from vmbox.integrity.receipts import verify_receipts

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


def _print_recovery(recovered: RecoveryResult) -> None:
    print(f"recovery: {recovered.status}")
    if recovered.manifest.mode == "offline_eval":
        print("offline evaluation session, not forensic evidence")
    print(f"chain: {recovered.chain_status}")
    print(f"journal: {recovered.journal_status}")
    print(f"receipts: {recovered.receipt_status}")
    print(f"recovered_events: {len(recovered.events)}")
    print(f"tombstones: {recovered.tombstones}")
    for gap in recovered.issues:
        seq = "unknown" if gap.seq_range is None else f"{gap.seq_range[0]}..{gap.seq_range[1]}"
        ts = "unknown" if gap.ts_range_ns is None else f"{gap.ts_range_ns[0]}..{gap.ts_range_ns[1]}"
        print(f"gap: {gap.kind} reason={gap.reason} seq={seq} ts_ns={ts}")


if __name__ == "__main__":
    raise SystemExit(main())
