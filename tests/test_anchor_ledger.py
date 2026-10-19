"""Offline anchor invariants; second-VM transport remains unverified."""

from dataclasses import replace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vmbox.anchor.ledger import AnchorLedger, EquivocationError
from vmbox.anchor.receipt_crypto import public_key_fingerprint
from vmbox.canonical import canonical_json
from vmbox.integrity.chain import ChainEntry, ChainVerification
from vmbox.integrity.receipts import read_receipts, verify_receipts
from vmbox.schema import AnchorInfo, Checkpoint, Receipt, SessionManifest


def _checkpoint(session: str, index: int, hex_digit: str = "a") -> Checkpoint:
    return Checkpoint(session, index, "sha256:" + hex_digit * 64, index, 1)


def _manifest(session: str, fingerprint: str) -> SessionManifest:
    return SessionManifest(1, session, str(uuid4()), "host", 1, "0", "sha256:" + "a" * 64,
                           "baseline", 4096, 1024, AnchorInfo("local", fingerprint))


def _chain(receipts: list[Receipt]) -> ChainVerification:
    return ChainVerification("ok", None, [ChainEntry(r.checkpoint.segment_index,
        "segment", r.checkpoint.segment_hash, r.checkpoint.seq_end) for r in receipts], "")


def test_idempotence_and_equivocation_record(tmp_path):
    key = Ed25519PrivateKey.generate()
    session = str(uuid4())
    ledger = AnchorLedger(tmp_path, key)
    checkpoint = _checkpoint(session, 0)
    first = ledger.accept(checkpoint)
    assert first.anchor_seq == 0
    path = tmp_path / "receipts" / session / "receipt_00000000.json"
    assert path.read_bytes() == canonical_json(first.to_dict())
    assert ledger.accept(checkpoint) == first
    assert len(list(path.parent.iterdir())) == 1
    with pytest.raises(EquivocationError):
        ledger.accept(_checkpoint(session, 0, "b"))
    conflicts = list((tmp_path / "equivocations" / session).iterdir())
    assert len(conflicts) == 1
    original = conflicts[0].read_bytes()
    with pytest.raises(EquivocationError):
        ledger.accept(_checkpoint(session, 0, "b"))
    assert conflicts[0].read_bytes() == original
    with pytest.raises(ValueError, match="same segment index"):
        ledger.accept(Checkpoint(session, 0, "sha256:" + "a" * 64, 99, 1))


def test_receipt_chain_and_anchor_tail(tmp_path):
    key = Ed25519PrivateKey.generate()
    session = str(uuid4())
    ledger = AnchorLedger(tmp_path / "anchor", key)
    receipts = [ledger.accept(_checkpoint(session, n)) for n in range(3)]
    host_dir = tmp_path / "host" / "receipts" / session
    host_dir.mkdir(parents=True)
    for receipt in receipts[:2]:
        (host_dir / f"receipt_{receipt.anchor_seq:08d}.json").write_bytes(
            canonical_json(receipt.to_dict()))
    manifest = _manifest(session, public_key_fingerprint(key.public_key()))
    chain = _chain(receipts)
    result = verify_receipts(manifest, chain, key.public_key(), tmp_path / "host")
    assert result.status == "ok" and "unconfirmed against anchor state" in result.reason
    result = verify_receipts(manifest, chain, key.public_key(), tmp_path / "host",
                             tmp_path / "anchor")
    assert result.status == "incomplete"
    assert result.reason == "host receipts end at anchor_seq 1, anchor has 2"
    assert read_receipts(ledger.root / "receipts" / session, key.public_key()) == receipts
    (host_dir / "receipt_00000001.json").unlink()
    (host_dir / "receipt_00000002.json").write_bytes(canonical_json(receipts[2].to_dict()))
    result = verify_receipts(manifest, chain, key.public_key(), tmp_path / "host")
    assert result.status == "tampered"


def test_wrong_key_swapped_signature_and_tampered_field(tmp_path):
    key = Ed25519PrivateKey.generate()
    wrong = Ed25519PrivateKey.generate()
    session = str(uuid4())
    ledger = AnchorLedger(tmp_path, key)
    receipts = [ledger.accept(_checkpoint(session, n)) for n in range(2)]
    directory = tmp_path / "receipts" / session
    manifest = _manifest(session, public_key_fingerprint(key.public_key()))
    result = verify_receipts(manifest, _chain(receipts), wrong.public_key(), tmp_path)
    assert result.status == "tampered"
    path = directory / "receipt_00000001.json"
    swapped = replace(receipts[1], signature=receipts[0].signature)
    path.write_bytes(canonical_json(swapped.to_dict()))
    result = verify_receipts(manifest, _chain(receipts), key.public_key(), tmp_path)
    assert result.status == "tampered"
    changed = replace(receipts[1], anchor_ts_ns=receipts[1].anchor_ts_ns + 1)
    path.write_bytes(canonical_json(changed.to_dict()))
    result = verify_receipts(manifest, _chain(receipts), key.public_key(), tmp_path)
    assert result.status == "tampered"


def test_reordered_receipts_and_segment_hash_mismatch(tmp_path):
    key = Ed25519PrivateKey.generate()
    session = str(uuid4())
    ledger = AnchorLedger(tmp_path, key)
    receipts = [ledger.accept(_checkpoint(session, n)) for n in range(2)]
    manifest = _manifest(session, public_key_fingerprint(key.public_key()))
    wrong_chain = ChainVerification("ok", None, [
        ChainEntry(0, "segment", "sha256:" + "f" * 64, 0),
        ChainEntry(1, "segment", receipts[1].checkpoint.segment_hash, 1),
    ], "")
    result = verify_receipts(manifest, wrong_chain, key.public_key(), tmp_path)
    assert result.status == "tampered" and "segment hash" in result.reason
    directory = tmp_path / "receipts" / session
    first = directory / "receipt_00000000.json"
    second = directory / "receipt_00000001.json"
    first.write_bytes(canonical_json(receipts[1].to_dict()))
    second.write_bytes(canonical_json(receipts[0].to_dict()))
    result = verify_receipts(manifest, _chain(receipts), key.public_key(), tmp_path)
    assert result.status == "tampered"
