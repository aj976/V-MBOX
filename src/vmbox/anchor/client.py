"""Resume missing host receipts from a verified local segment chain."""

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vmbox.anchor.ledger import write_once
from vmbox.anchor.receipt_crypto import public_key_fingerprint
from vmbox.anchor.transport import send_checkpoint
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.receipts import read_receipts
from vmbox.integrity.segment import verify_segment
from vmbox.integrity.tombstone import verify_tombstone
from vmbox.schema import Checkpoint, SessionManifest


@dataclass(frozen=True)
class SyncResult:
    anchored_segments: int
    pending_segments: int
    outage: str | None


def sync_receipts(root: Path, manifest: SessionManifest, public_key: Ed25519PublicKey,
                  auth_key: bytes, *, timeout: float = 5) -> SyncResult:
    """Never silently treat a missed checkpoint as anchored.

    Network failures leave a valid chained-only suffix. Protocol or signature
    failures are fatal. Second-VM behavior is unverified until run there.
    """
    if manifest.mode != "live" or manifest.anchor is None:
        raise ValueError("receipt sync requires a live session with anchor")
    if public_key_fingerprint(public_key) != manifest.anchor.pubkey_fingerprint:
        raise ValueError("anchor public key fingerprint mismatch")
    chain = verify_chain(root, manifest)
    if chain.status != "ok":
        raise ValueError(f"cannot checkpoint {chain.status} chain")
    receipt_dir = root / "receipts" / manifest.session_id
    existing = read_receipts(receipt_dir, public_key)
    if len(existing) > len(chain.entries):
        raise ValueError("host receipts exceed local chain")
    checkpoint_by_index: dict[int, Checkpoint] = {}
    previous = "sha256:" + manifest_genesis(manifest).hex()
    for entry in chain.entries:
        if entry.kind == "segment":
            verified = verify_segment(root / f"seg_{entry.index:08d}.vseg", previous)
            if verified.status != "ok" or verified.header is None:
                raise ValueError("checkpoint segment failed verification")
            timestamp = verified.header.ts_end_ns
        else:
            verified_tomb = verify_tombstone(root / f"seg_{entry.index:08d}.tomb",
                                             previous, entry.index)
            if verified_tomb.tombstone is None:
                raise ValueError("checkpoint tombstone failed verification")
            timestamp = verified_tomb.tombstone.ts_end_ns
        if entry.seq_end is None:
            raise ValueError("checkpoint sequence end is unknown")
        checkpoint_by_index[entry.index] = Checkpoint(
            manifest.session_id, entry.index, entry.segment_hash, entry.seq_end, timestamp
        )
        previous = entry.segment_hash
    for offset, receipt in enumerate(existing):
        if receipt.checkpoint.segment_index != chain.entries[offset].index:
            raise ValueError("host receipt log is not a prefix of the chain")
        expected = checkpoint_by_index.get(receipt.checkpoint.segment_index)
        if expected != receipt.checkpoint:
            raise ValueError("host receipt disagrees with local chain checkpoint")
    anchored = len(existing)
    for entry in chain.entries[anchored:]:
        checkpoint = checkpoint_by_index[entry.index]
        try:
            receipt = send_checkpoint(manifest.anchor.endpoint, checkpoint, auth_key,
                                      public_key, timeout=timeout)
        except (OSError, TimeoutError) as exc:
            return SyncResult(anchored, len(chain.entries) - anchored, str(exc))
        if receipt.anchor_seq != anchored:
            raise ValueError("anchor receipt sequence is not the expected next value")
        write_once(receipt_dir / f"receipt_{receipt.anchor_seq:08d}.json",
                   receipt.to_json())
        anchored += 1
    return SyncResult(anchored, len(chain.entries) - anchored, None)
