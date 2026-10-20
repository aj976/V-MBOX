"""Verify signed receipt logs; host-only tail state remains unconfirmed."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vmbox.anchor.receipt_crypto import (
    GENESIS_RECEIPT_HASH,
    public_key_fingerprint,
    receipt_hash,
    verify_receipt_signature,
)
from vmbox.canonical import canonical_json
from vmbox.integrity.chain import ChainVerification
from vmbox.schema import Receipt, SessionManifest

_RECEIPT_NAME = re.compile(r"receipt_([0-9]{8})\.json\Z")


def read_receipts(directory: Path, public_key: Ed25519PublicKey) -> list[Receipt]:
    if not directory.exists():
        return []
    paths = sorted(directory.iterdir())
    if any(not path.is_file() or _RECEIPT_NAME.fullmatch(path.name) is None for path in paths):
        raise ValueError("unrecognized receipt file")
    receipts: list[Receipt] = []
    expected_hash = GENESIS_RECEIPT_HASH
    previous_index = -1
    for seq, path in enumerate(paths):
        if path.name != f"receipt_{seq:08d}.json":
            raise ValueError("receipt sequence gap or reordering")
        raw = path.read_bytes()
        try:
            document = json.loads(raw)
            receipt = Receipt.from_dict(document)
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("invalid receipt file") from exc
        if raw != canonical_json(receipt.to_dict()):
            raise ValueError("noncanonical receipt file")
        if receipt.anchor_seq != seq or receipt.prev_receipt_hash != expected_hash:
            raise ValueError("receipt chain mismatch")
        if receipt.checkpoint.segment_index <= previous_index:
            raise ValueError("receipt segment indexes must increase")
        verify_receipt_signature(public_key, receipt)
        expected_hash = receipt_hash(receipt)
        previous_index = receipt.checkpoint.segment_index
        receipts.append(receipt)
    return receipts


@dataclass(frozen=True)
class ReceiptVerification:
    status: Literal["ok", "incomplete", "tampered"]
    reason: str
    anchored_through: int


def verify_receipts(manifest: SessionManifest, chain: ChainVerification,
                    public_key: Ed25519PublicKey, host_root: Path,
                    anchor_export_root: Path | None = None) -> ReceiptVerification:
    if manifest.mode == "offline_eval":
        return ReceiptVerification(
            "incomplete", "offline evaluation receipts do not establish forensic integrity", -1
        )
    if manifest.anchor is None:
        return ReceiptVerification("tampered", "live manifest has no anchor", -1)
    if public_key_fingerprint(public_key) != manifest.anchor.pubkey_fingerprint:
        return ReceiptVerification("tampered", "anchor public key fingerprint mismatch", -1)
    session = manifest.session_id
    try:
        host = read_receipts(host_root / "receipts" / session, public_key)
        anchor = (read_receipts(anchor_export_root / "receipts" / session, public_key)
                  if anchor_export_root is not None else None)
    except ValueError as exc:
        return ReceiptVerification("tampered", str(exc), -1)
    by_index = {entry.index: entry for entry in chain.entries}
    for receipt in host + (anchor or []):
        checkpoint = receipt.checkpoint
        entry = by_index.get(checkpoint.segment_index)
        if checkpoint.session_id != session or entry is None:
            return ReceiptVerification("tampered", "receipt segment absent from host chain", -1)
        if checkpoint.segment_hash != entry.segment_hash:
            return ReceiptVerification("tampered", "receipt segment hash mismatch", -1)
        if entry.seq_end is not None and checkpoint.seq_end != entry.seq_end:
            return ReceiptVerification("tampered", "receipt seq_end mismatch", -1)
    through = len(host) - 1
    if anchor is None:
        if through < 0:
            return ReceiptVerification("ok", "no host receipts; "
                                       "unconfirmed against anchor state", through)
        return ReceiptVerification("ok", f"anchored through anchor_seq {through}; "
                                   "unconfirmed against anchor state", through)
    if host != anchor[:len(host)]:
        return ReceiptVerification("tampered", "host and anchor receipt logs differ", through)
    if len(host) < len(anchor):
        return ReceiptVerification("incomplete", f"host receipts end at anchor_seq {through}, "
                                   f"anchor has {len(anchor) - 1}", through)
    if len(host) > len(anchor):
        return ReceiptVerification("tampered", "host receipt log exceeds anchor export", through)
    if through < 0:
        return ReceiptVerification("ok", "no receipts in host or anchor export; "
                                   "confirmed against anchor state", through)
    return ReceiptVerification("ok", f"anchored through anchor_seq {through}; "
                               "confirmed against anchor state", through)
