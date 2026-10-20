"""Read-only recovery of surviving, integrity-qualified evidence."""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from vmbox.integrity.chain import verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.segment import verify_segment
from vmbox.integrity.tombstone import verify_tombstone
from vmbox.schema import Event, Gap, SessionManifest
from vmbox.store.journal import recover_journal
from vmbox.store.manifest import read_manifest

RecoveryStatus = Literal["ok", "incomplete", "tampered"]
IntegrityLevel = Literal["anchored", "chained", "journal_only"]
@dataclass(frozen=True)
class RecoveredEvent:
    event: Event
    integrity: IntegrityLevel


@dataclass(frozen=True)
class RecoveryResult:
    manifest: SessionManifest
    events: tuple[RecoveredEvent, ...]
    issues: tuple[Gap, ...]
    status: RecoveryStatus
    chain_status: RecoveryStatus
    journal_status: Literal["readable", "incomplete", "missing"]
    receipt_status: str
    tombstones: int
    journal_evicted_frames: int | None
    chain_head_hash: str
    segment_count: int


def _gap(kind: str, reason: str, seq_range: Sequence[int] | None = None,
         ts_range_ns: Sequence[int] | None = None,
         last: Event | None = None, next_event: Event | None = None) -> Gap:
    return Gap.from_dict({
        "kind": kind, "reason": reason,
        "seq_range": list(seq_range) if seq_range is not None else None,
        "ts_range_ns": list(ts_range_ns) if ts_range_ns is not None else None,
        "last_valid_seq": last.seq if last is not None else None,
        "last_valid_ts_ns": last.ts_ns if last is not None else None,
        "next_valid_seq": next_event.seq if next_event is not None else None,
        "next_valid_ts_ns": next_event.ts_ns if next_event is not None else None,
    })


def _neighbors(events: tuple[RecoveredEvent, ...], start: int, end: int
               ) -> tuple[Event | None, Event | None]:
    before = next((item.event for item in reversed(events) if item.event.seq < start), None)
    after = next((item.event for item in events if item.event.seq > end), None)
    return before, after


def recover_evidence(directory: Path, *, anchor_public_key: Path | None = None,
                     anchor_receipts: Path | None = None) -> RecoveryResult:
    """Keep verified sealed records and CRC-readable journal records distinct."""
    if anchor_receipts is not None and anchor_public_key is None:
        raise ValueError("anchor receipt export requires an anchor public key")
    manifest = read_manifest(directory / "manifest.json")
    chain = verify_chain(directory, manifest)
    issues: list[Gap] = []
    if chain.status != "ok":
        issues.append(_gap("incomplete_write", f"chain_{chain.status}"))
    try:
        journal = recover_journal(directory / "journal.bin")
        journal_status: Literal["readable", "incomplete", "missing"] = (
            "incomplete" if journal.incomplete_reason else "readable"
        )
        if journal.incomplete_reason:
            reason = ("crc_failure_unreadable_payload" if "CRC" in journal.incomplete_reason
                      else "torn_frame_no_header" if "short journal frame header"
                      in journal.incomplete_reason else "journal_unreadable")
            issues.append(_gap("incomplete_write", reason))
        journal_events = journal.events
        evicted_frames: int | None = journal.evicted_frames
    except FileNotFoundError:
        journal_status = "missing"
        journal_events = []
        evicted_frames = None
        issues.append(_gap("incomplete_write", "journal_missing"))

    receipt_status = "not applicable to offline evaluation" if manifest.mode == "offline_eval" \
        else "not checked against an anchor key"
    anchored_through = -1
    if manifest.mode == "live" and anchor_public_key is not None and chain.status == "ok":
        from vmbox.anchor.receipt_crypto import load_public_key
        from vmbox.integrity.receipts import read_receipts, verify_receipts

        try:
            public_key = load_public_key(anchor_public_key)
            receipt_check = verify_receipts(manifest, chain, public_key, directory,
                                            anchor_receipts)
        except (OSError, ValueError) as exc:
            receipt_status = f"tampered: {exc}"
            issues.append(_gap("incomplete_write", "receipt_verification_failed"))
        else:
            receipt_status = f"{receipt_check.status}: {receipt_check.reason}"
            if receipt_check.status in {"ok", "incomplete"}:
                accepted = read_receipts(directory / "receipts" / manifest.session_id,
                                         public_key)
                anchored_through = (accepted[-1].checkpoint.segment_index
                                    if accepted else -1)
            if receipt_check.status != "ok":
                issues.append(_gap("incomplete_write", "receipt_verification_failed"))
    elif manifest.mode == "live" and anchor_public_key is not None:
        receipt_status = "not checked because the local chain is not complete"

    by_id: dict[str, RecoveredEvent] = {}
    previous = "sha256:" + manifest_genesis(manifest).hex()
    for entry in chain.entries:
        if entry.kind == "segment":
            segment = verify_segment(directory / f"seg_{entry.index:08d}.vseg", previous)
            if segment.status != "ok":
                raise ValueError("verified chain prefix changed during recovery")
            level: IntegrityLevel = ("anchored" if entry.index <= anchored_through
                                     and manifest.mode == "live" else "chained")
            for event in segment.events:
                if event.session_id != manifest.session_id or event.boot_id != manifest.boot_id:
                    raise ValueError("sealed event session/boot mismatch")
                by_id[event.event_id] = RecoveredEvent(event, level)
        else:
            tomb = verify_tombstone(directory / f"seg_{entry.index:08d}.tomb", previous,
                                    entry.index)
            if tomb.status != "metadata_valid" or tomb.tombstone is None:
                raise ValueError("verified tombstone changed during recovery")
            metadata = tomb.tombstone
            issues.append(_gap("tombstone", "budget_eviction",
                               (metadata.seq_start, metadata.seq_end),
                               (metadata.ts_start_ns, metadata.ts_end_ns)))
        previous = entry.segment_hash
    for event in journal_events:
        if event.session_id != manifest.session_id or event.boot_id != manifest.boot_id:
            raise ValueError("journal event session/boot mismatch")
        existing = by_id.get(event.event_id)
        if existing is not None and existing.event != event:
            raise ValueError("sealed and journal copies of an event disagree")
        if existing is None:
            by_id[event.event_id] = RecoveredEvent(event, "journal_only")
    ordered = tuple(sorted(by_id.values(), key=lambda item: item.event.seq))
    if len({item.event.seq for item in ordered}) != len(ordered):
        raise ValueError("two different recovered events share a sequence")
    for item in ordered:
        if item.event.event_type == "CAPTURE_GAP":
            issues.append(_gap("capture_gap", "collector_reported_gap",
                               (item.event.seq, item.event.seq),
                               (item.event.ts_ns, item.event.ts_ns)))
    for left, right in zip(ordered, ordered[1:], strict=False):
        if right.event.seq > left.event.seq + 1:
            issues.append(_gap("seq_gap", "missing_sequence",
                               (left.event.seq + 1, right.event.seq - 1),
                               (min(left.event.ts_ns, right.event.ts_ns),
                                max(left.event.ts_ns, right.event.ts_ns)),
                               left.event, right.event))
    if manifest.mode == "live" and ordered and ordered[-1].event.event_type != "COLLECTOR_STOP":
        issues.append(_gap("interruption", "no_stop_marker", last=ordered[-1].event))
    completed_issues: list[Gap] = []
    for issue in issues:
        if issue.kind == "seq_gap" or issue.kind == "interruption":
            completed_issues.append(issue)
            continue
        if issue.seq_range is not None:
            previous_event, next_event = _neighbors(
                ordered, issue.seq_range[0], issue.seq_range[1]
            )
        elif issue.reason in {"crc_failure_unreadable_payload", "torn_frame_no_header",
                              "journal_unreadable"} and journal_events:
            previous_event = journal_events[-1]
            next_event = next((item.event for item in ordered
                               if item.event.seq > previous_event.seq), None)
        elif issue.reason in {"chain_incomplete", "chain_tampered"} and chain.entries:
            last_seq = chain.entries[-1].seq_end
            previous_event = next((item.event for item in reversed(ordered)
                                   if last_seq is not None and item.event.seq <= last_seq), None)
            next_event = next((item.event for item in ordered
                               if last_seq is not None and item.event.seq > last_seq), None)
        else:
            previous_event = None
            next_event = ordered[0].event if ordered else None
        completed_issues.append(_gap(issue.kind, issue.reason,
                                     tuple(issue.seq_range) if issue.seq_range else None,
                                     tuple(issue.ts_range_ns) if issue.ts_range_ns else None,
                                     previous_event, next_event))
    status: RecoveryStatus = "ok"
    if chain.status == "tampered" or receipt_status.startswith("tampered:"):
        status = "tampered"
    elif chain.status == "incomplete" or journal_status != "readable" or completed_issues:
        status = "incomplete"
    return RecoveryResult(manifest, ordered, tuple(completed_issues), status, chain.status,
                          journal_status, receipt_status,
                          sum(issue.kind == "tombstone" for issue in completed_issues),
                          evicted_frames, chain.last_hash,
                          sum(entry.kind == "segment" for entry in chain.entries))
