"""Build schema-defined reconstruction output from qualified recovered evidence."""

from vmbox.reconstruct.relations import build_relations, build_timeline
from vmbox.recover.evidence import RecoveryResult
from vmbox.schema import Reconstruction


def build_reconstruction(recovered: RecoveryResult) -> Reconstruction:
    limitations = [
        "A matching local hash chain verifies stored bytes, not event truth or completeness.",
        "Host timestamps may be inaccurate; timeline order follows sequence numbers.",
    ]
    if recovered.manifest.mode == "offline_eval":
        limitations.append("Offline evaluation session, not forensic evidence.")
    else:
        limitations.append(f"Receipt state: {recovered.receipt_status}.")
    if any(item.integrity == "journal_only" for item in recovered.events):
        limitations.append("Journal-only events have CRC framing but no hash-chain integrity.")
    if recovered.tombstones:
        limitations.append("Tombstoned sealed bodies are no longer verifiable or recoverable.")
    if recovered.journal_evicted_frames is not None and recovered.journal_evicted_frames:
        limitations.append("The journal ring overwrote older frames; their contents are gone.")
    if recovered.chain_status != "ok":
        limitations.append(f"Local chain state is {recovered.chain_status}; only its verified "
                           "prefix was reconstructed.")
    for gap in recovered.issues:
        unknown = []
        if gap.seq_range is None:
            unknown.append("sequence")
        if gap.ts_range_ns is None:
            unknown.append("timestamp")
        if unknown:
            last = (f"after seq {gap.last_valid_seq}" if gap.last_valid_seq is not None
                    else "with no preceding valid sequence")
            next_text = (f", before seq {gap.next_valid_seq}"
                         if gap.next_valid_seq is not None else ", upper bound unknown")
            limitations.append(f"Unknown {' and '.join(unknown)} bounds for "
                               f"{gap.reason}: gap begins {last}{next_text}.")
    return Reconstruction(
        reconstruction_format_version=1,
        timeline=build_timeline(recovered.events),
        relations=build_relations(recovered.events),
        gaps=list(recovered.issues),
        limitations=limitations,
    )
