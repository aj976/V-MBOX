"""Domain-separated Ed25519 receipt signatures and per-session hash links."""

from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vmbox.canonical import canonical_json
from vmbox.schema import Checkpoint, Receipt

DOMAIN = b"vmbox-receipt-v1\n"
GENESIS_RECEIPT_HASH = "sha256:" + "0" * 64


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + sha256(raw).hexdigest()


def load_public_key(path: Path) -> Ed25519PublicKey:
    loaded = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("anchor public key must be Ed25519")
    return loaded


def receipt_signing_bytes(checkpoint: Checkpoint, anchor_ts_ns: int,
                          anchor_seq: int, prev_receipt_hash: str) -> bytes:
    body = {"checkpoint": checkpoint.to_dict(), "anchor_ts_ns": anchor_ts_ns,
            "anchor_seq": anchor_seq, "prev_receipt_hash": prev_receipt_hash}
    return DOMAIN + canonical_json(body)


def sign_receipt(private_key: Ed25519PrivateKey, checkpoint: Checkpoint,
                 anchor_ts_ns: int, anchor_seq: int, prev_receipt_hash: str) -> Receipt:
    message = receipt_signing_bytes(checkpoint, anchor_ts_ns, anchor_seq, prev_receipt_hash)
    signature = "ed25519:" + private_key.sign(message).hex()
    return Receipt(checkpoint, anchor_ts_ns, anchor_seq, prev_receipt_hash, signature)


def verify_receipt_signature(public_key: Ed25519PublicKey, receipt: Receipt) -> None:
    message = receipt_signing_bytes(receipt.checkpoint, receipt.anchor_ts_ns,
                                    receipt.anchor_seq, receipt.prev_receipt_hash)
    try:
        public_key.verify(bytes.fromhex(receipt.signature.removeprefix("ed25519:")), message)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("receipt signature verification failed") from exc


def receipt_hash(receipt: Receipt) -> str:
    return "sha256:" + sha256(canonical_json(asdict(receipt))).hexdigest()
