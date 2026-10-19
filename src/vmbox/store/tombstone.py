"""Write-once tombstone replacement for an evicted sealed segment."""

import os
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from vmbox.canonical import canonical_json
from vmbox.integrity.segment import verify_segment
from vmbox.schema import Tombstone
from vmbox.store.segment import SegmentFooter, SegmentHeader


def make_tombstone(header: SegmentHeader, footer: SegmentFooter,
                   evicted_ts_ns: int) -> Tombstone:
    if evicted_ts_ns < 0:
        raise ValueError("negative eviction timestamp")
    content = {
        "index": header.index,
        "seq_start": header.seq_start,
        "seq_end": header.seq_end,
        "record_count": header.record_count,
        "ts_start_ns": header.ts_start_ns,
        "ts_end_ns": header.ts_end_ns,
        "prev_hash": header.prev_hash,
        "segment_hash": footer.segment_hash,
        "evicted_reason": "budget",
        "evicted_ts_ns": evicted_ts_ns,
    }
    digest = "sha256:" + sha256(canonical_json(content)).hexdigest()
    return Tombstone.from_dict({**content, "tombstone_hash": digest})


def write_tombstone(path: Path, tombstone: Tombstone) -> None:
    temp = path.with_name(path.name + ".tmp")
    if path.exists() or temp.exists():
        raise FileExistsError(path)
    with temp.open("xb") as stream:
        stream.write(canonical_json(asdict(tombstone)) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    # Windows os.rename refuses to overwrite a destination. Crash behavior
    # remains unverified until run on Windows VM.
    os.rename(temp, path)


def evict_segment(segment_path: Path, tombstone_path: Path,
                  expected_prev_hash: str, evicted_ts_ns: int) -> Tombstone:
    """Publish tombstone before deleting body; a crash with both is a conflict."""
    verified = verify_segment(segment_path, expected_prev_hash)
    if verified.status != "ok" or verified.header is None or verified.footer is None:
        raise ValueError("cannot evict an unverified segment")
    tombstone = make_tombstone(verified.header, verified.footer, evicted_ts_ns)
    write_tombstone(tombstone_path, tombstone)
    segment_path.unlink()
    return tombstone
