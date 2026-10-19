"""Offline, write-once per-session anchor ledger. Second-VM transport is unverified."""

import os
import re
import time
from hashlib import sha256
from pathlib import Path
from threading import Lock
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vmbox.anchor.receipt_crypto import GENESIS_RECEIPT_HASH, receipt_hash, sign_receipt
from vmbox.canonical import canonical_json
from vmbox.schema import Checkpoint, Receipt


class EquivocationError(ValueError):
    """An index was submitted with a different segment hash."""


def _session_id(value: str) -> str:
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("session_id must be a canonical UUID")
    return value


def write_once(path: Path, data: bytes) -> None:
    """Create and fsync a file before returning; never replace existing evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # A failed write remains visible as incomplete evidence; never erase it.
        raise


class AnchorLedger:
    def __init__(self, root: Path, private_key: Ed25519PrivateKey) -> None:
        self.root = root
        self.private_key = private_key
        self._lock = Lock()

    def accept(self, checkpoint: Checkpoint) -> Receipt:
        session = _session_id(checkpoint.session_id)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", checkpoint.segment_hash) is None:
            raise ValueError("checkpoint segment_hash is invalid")
        from vmbox.integrity.receipts import read_receipts

        with self._lock:
            directory = self.root / "receipts" / session
            previous = read_receipts(directory, self.private_key.public_key())
            for receipt in previous:
                if receipt.checkpoint == checkpoint:
                    return receipt
                if receipt.checkpoint.segment_index == checkpoint.segment_index:
                    if receipt.checkpoint.segment_hash != checkpoint.segment_hash:
                        digest = sha256(canonical_json(checkpoint.to_dict())).hexdigest()
                        name = f"conflict_{checkpoint.segment_index:08d}_{digest}.json"
                        path = self.root / "equivocations" / session / name
                        if not path.exists():
                            record = {"accepted_checkpoint": receipt.checkpoint.to_dict(),
                                      "rejected_checkpoint": checkpoint.to_dict(),
                                      "anchor_ts_ns": time.time_ns()}
                            write_once(path, canonical_json(record))
                        raise EquivocationError("conflicting segment hash recorded")
                    raise ValueError("same segment index has a different checkpoint")
            if previous and checkpoint.segment_index <= previous[-1].checkpoint.segment_index:
                raise ValueError("segment_index must increase")
            anchor_seq = len(previous)
            prev_hash = receipt_hash(previous[-1]) if previous else GENESIS_RECEIPT_HASH
            receipt = sign_receipt(self.private_key, checkpoint, time.time_ns(),
                                   anchor_seq, prev_hash)
            write_once(directory / f"receipt_{anchor_seq:08d}.json",
                       canonical_json(receipt.to_dict()))
            return receipt
