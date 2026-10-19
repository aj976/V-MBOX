"""M4 signature encoding, domain separation, and tamper tests."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vmbox.anchor.receipt_crypto import (
    GENESIS_RECEIPT_HASH,
    receipt_hash,
    sign_receipt,
    verify_receipt_signature,
)
from vmbox.schema import Checkpoint, Receipt


def checkpoint(index=0, digest="sha256:" + "a" * 64):
    return Checkpoint("00000000-0000-4000-8000-000000000001", index, digest, index, 10)


def test_receipt_signature_tampered_field_swapped_signature_and_wrong_key():
    key = Ed25519PrivateKey.generate()
    first = sign_receipt(key, checkpoint(), 20, 0, GENESIS_RECEIPT_HASH)
    second = sign_receipt(key, checkpoint(1), 21, 1, receipt_hash(first))
    verify_receipt_signature(key.public_key(), first)
    assert receipt_hash(first) != receipt_hash(second)
    tampered = Receipt(first.checkpoint, 21, first.anchor_seq,
                       first.prev_receipt_hash, first.signature)
    swapped = Receipt(first.checkpoint, first.anchor_ts_ns, first.anchor_seq,
                      first.prev_receipt_hash, second.signature)
    for invalid in (tampered, swapped):
        with pytest.raises(ValueError, match="signature"):
            verify_receipt_signature(key.public_key(), invalid)
    with pytest.raises(ValueError, match="signature"):
        verify_receipt_signature(Ed25519PrivateKey.generate().public_key(), first)
