"""Synthetic trust-boundary probes; VM behavior remains unverified."""

import shutil
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_relations import _base

from vmbox.anchor.ledger import AnchorLedger
from vmbox.anchor.receipt_crypto import public_key_fingerprint
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.receipts import verify_receipts
from vmbox.schema import AnchorInfo, Checkpoint, Event, SessionManifest
from vmbox.store.manifest import write_manifest
from vmbox.store.segment import SelectionStats, seal_segment

HASH = "sha256:" + "a" * 64


def _fixture(tmp_path: Path) -> tuple[Path, Path, SessionManifest, Ed25519PrivateKey,
                                      tuple[Event, Event]]:
    key = Ed25519PrivateKey.generate()
    session = str(uuid4())
    boot = str(uuid4())
    manifest = SessionManifest(1, "live", session, boot, "synthetic-host", 1,
                               "synthetic", HASH, "fixed", 8192, 1024,
                               AnchorInfo("synthetic-anchor",
                                          public_key_fingerprint(key.public_key())))
    host = tmp_path / "host"
    host.mkdir()
    write_manifest(host / "manifest.json", manifest)
    base = _base(tmp_path)
    events = tuple(replace(base, session_id=session, boot_id=boot, seq=seq,
                           event_id=str(uuid5(UUID(session), str(seq))), ts_ns=100 + seq)
                   for seq in range(2))
    previous = "sha256:" + manifest_genesis(manifest).hex()
    footers = []
    for index, event in enumerate(events):
        footer = seal_segment(host / f"seg_{index:08d}.vseg", index=index,
                              events=[event], prev_hash=previous, strategy="fixed",
                              selection_stats=SelectionStats(1, 1, 0,
                                                             {event.event_type: 1}, 0))
        footers.append(footer)
        previous = footer.segment_hash
    anchor = tmp_path / "anchor"
    ledger = AnchorLedger(anchor, key)
    receipt = ledger.accept(Checkpoint(session, 1, footers[-1].segment_hash, 1, 1))
    host_receipts = host / "receipts" / session
    host_receipts.mkdir(parents=True)
    shutil.copy2(anchor / "receipts" / session / "receipt_00000000.json",
                 host_receipts / f"receipt_{receipt.anchor_seq:08d}.json")
    return host, anchor, manifest, key, (events[0], events[1])


def test_full_local_chain_rewrite_needs_anchor_to_expose_it(tmp_path: Path) -> None:
    host, anchor, manifest, key, events = _fixture(tmp_path)
    original = verify_chain(host, manifest)
    assert original.status == "ok"
    assert verify_receipts(manifest, original, key.public_key(), host, anchor).status == "ok"
    rewritten = tmp_path / "rewritten-copy"
    shutil.copytree(host, rewritten)
    for path in rewritten.glob("seg_*.vseg"):
        path.unlink()  # Mutation is confined to the copied attacker simulation.
    changed = replace(events[0], data={**events[0].data, "synthetic_change": True})
    previous = "sha256:" + manifest_genesis(manifest).hex()
    for index, event in enumerate((changed, events[1])):
        footer = seal_segment(rewritten / f"seg_{index:08d}.vseg", index=index,
                              events=[event], prev_hash=previous, strategy="fixed",
                              selection_stats=SelectionStats(1, 1, 0,
                                                             {event.event_type: 1}, 0))
        previous = footer.segment_hash
    local = verify_chain(rewritten, manifest)
    assert local.status == "ok"
    assert local.last_hash != original.last_hash
    assert verify_receipts(manifest, local, key.public_key(), rewritten).status == "tampered"


def test_anchor_outage_does_not_upgrade_local_chain(tmp_path: Path) -> None:
    host, anchor, manifest, key, _ = _fixture(tmp_path)
    receipt_dir = host / "receipts" / manifest.session_id
    shutil.rmtree(receipt_dir)
    chain = verify_chain(host, manifest)
    assert chain.status == "ok"
    host_only = verify_receipts(manifest, chain, key.public_key(), host)
    assert host_only.anchored_through == -1
    assert "unconfirmed against anchor state" in host_only.reason
    exported = verify_receipts(manifest, chain, key.public_key(), host, anchor)
    assert exported.status == "incomplete"


def test_pre_seal_fabrication_suppression_and_timestamp_change_are_not_chain_errors(
    tmp_path: Path,
) -> None:
    host, _, manifest, _, events = _fixture(tmp_path)
    for path in host.glob("seg_*.vseg"):
        path.unlink()  # Synthetic collector input change, never original evidence.
    changed = replace(events[0], ts_ns=events[0].ts_ns + 1_000_000,
                      data={**events[0].data, "synthetic_field": "altered"})
    seal_segment(host / "seg_00000000.vseg", index=0, events=[changed],
                 prev_hash="sha256:" + manifest_genesis(manifest).hex(),
                 strategy="fixed", selection_stats=SelectionStats(
                     1, 1, 0, {changed.event_type: 1}, 0))
    assert verify_chain(host, manifest).status == "ok"
