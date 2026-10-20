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
    record = subcommands.add_parser("record", help="record Sysmon events on the lab VM")
    record.add_argument("--anchor-endpoint", required=True)
    record.add_argument("--anchor-pubkey", type=Path, required=True)
    record.add_argument("--anchor-auth-key", type=Path, required=True)
    record.add_argument("--out", type=Path, required=True)
    record.add_argument("--duration", type=float, required=True)
    record.add_argument("--strategy", choices=("fifo_ring", "fixed", "priority",
                                               "context_aware"), default="context_aware")
    record.add_argument("--budget-bytes", type=int, required=True)
    record.add_argument("--journal-bytes", type=int, default=8 * 1024 * 1024)
    record.add_argument("--segment-events", type=int, default=128)
    record.add_argument("--queue-capacity", type=int, default=10000)
    record.add_argument("--sysmon-config", type=Path, default=Path("docs/sysmon.xml"))
    record.add_argument("--tee-raw", type=Path)
    keygen = subcommands.add_parser("anchor-keygen", help="create anchor-only keys")
    keygen.add_argument("--out", type=Path, required=True)
    anchor = subcommands.add_parser("anchor", help="serve signed checkpoints")
    anchor.add_argument("--listen", required=True)
    anchor.add_argument("--key", type=Path, required=True)
    anchor.add_argument("--auth-key", type=Path, required=True)
    anchor.add_argument("--store", type=Path, required=True)
    sync = subcommands.add_parser("anchor-sync", help="retry pending signed checkpoints")
    sync.add_argument("--evidence", type=Path, required=True)
    sync.add_argument("--anchor-pubkey", type=Path, required=True)
    sync.add_argument("--anchor-auth-key", type=Path, required=True)
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
    if args.command == "anchor-keygen":
        from vmbox.anchor.keys import create_anchor_keys

        try:
            fingerprint = create_anchor_keys(args.out)
        except (OSError, ValueError) as exc:
            print(f"anchor key generation failed: {exc}")
            return 2
        print(f"public_key_fingerprint: {fingerprint}")
        print("keep private.pem on the anchor VM only; copy public.pem and auth.key "
              "to the monitored VM through an isolated channel")
        return 0
    if args.command == "anchor":
        from vmbox.anchor.keys import load_private_key
        from vmbox.anchor.ledger import AnchorLedger
        from vmbox.anchor.transport import read_auth_key, serve_anchor

        try:
            private = load_private_key(args.key)
            secret = read_auth_key(args.auth_key)
            server = serve_anchor(args.listen, AnchorLedger(args.store, private), secret)
            print(f"anchor_listening: {args.listen}", flush=True)
            with server:
                server.serve_forever()
        except KeyboardInterrupt:
            return 0
        except (OSError, ValueError) as exc:
            print(f"anchor failed: {exc}")
            return 2
        return 0
    if args.command == "anchor-sync":
        from vmbox.anchor.client import sync_receipts
        from vmbox.anchor.receipt_crypto import load_public_key
        from vmbox.anchor.transport import read_auth_key

        try:
            manifest = read_manifest(args.evidence / "manifest.json")
            result = sync_receipts(args.evidence, manifest,
                                   load_public_key(args.anchor_pubkey),
                                   read_auth_key(args.anchor_auth_key))
        except (OSError, ValueError) as exc:
            print(f"anchor sync failed: {exc}")
            return 2
        print(f"anchored_segments: {result.anchored_segments}")
        print(f"pending_segments: {result.pending_segments}")
        if result.outage is not None:
            print(f"anchor outage: {result.outage}")
        return 3 if result.pending_segments else 0
    if args.command == "record":
        from vmbox.record.command import record_sysmon

        try:
            digest, seen, overflow, pending = record_sysmon(
                output=args.out, duration_s=args.duration,
                strategy_name=args.strategy, budget_bytes=args.budget_bytes,
                journal_bytes=args.journal_bytes, segment_events=args.segment_events,
                queue_capacity=args.queue_capacity,
                sysmon_config=args.sysmon_config,
                anchor_endpoint=args.anchor_endpoint,
                anchor_pubkey=args.anchor_pubkey,
                anchor_auth_key=args.anchor_auth_key, trace_path=args.tee_raw,
            )
        except (ImportError, OSError, ValueError, RuntimeError) as exc:
            print(f"record failed: {exc}; existing output, if any, is incomplete")
            return 2
        print(f"trace_hash: {digest}")
        print(f"events_seen: {seen}")
        print(f"collector_queue_overflow: {overflow}")
        print(f"anchor_pending_segments: {pending}")
        print("sysmon_upstream_lost: not measured")
        return 3 if pending or overflow else 0
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
