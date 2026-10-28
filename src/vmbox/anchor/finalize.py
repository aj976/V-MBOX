"""Complete pending checkpoints and confirm the anchor's receipt history."""

from pathlib import Path

from vmbox.anchor.client import sync_receipts
from vmbox.anchor.ledger import write_once
from vmbox.anchor.receipt_crypto import load_public_key
from vmbox.anchor.transport import fetch_receipt_log, read_auth_key
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.receipts import verify_receipts
from vmbox.operator import default_export
from vmbox.recover.evidence import recover_evidence
from vmbox.store.manifest import read_manifest


def finalize_evidence(evidence: Path, public_path: Path, auth_path: Path,
                      export_path: Path | None = None) -> tuple[str, str, Path]:
    """Return integrity status, receipt status, and write-once export path.

    A failed network request leaves evidence unchanged and does not claim that
    the anchor is in sync. Cross-VM behavior is unverified until run there.
    """
    manifest = read_manifest(evidence / "manifest.json")
    if manifest.mode != "live" or manifest.anchor is None:
        raise ValueError("finalize requires a live session")
    public = load_public_key(public_path)
    auth = read_auth_key(auth_path)
    synced = sync_receipts(evidence, manifest, public, auth)
    if synced.pending_segments:
        raise ConnectionError(f"{synced.pending_segments} segments remain pending: "
                              f"{synced.outage}")
    receipts = fetch_receipt_log(manifest.anchor.endpoint, manifest.session_id,
                                 auth, public)
    export = export_path or default_export(evidence)
    if export.exists():
        raise FileExistsError(f"anchor export already exists: {export}; choose --out for a retry")
    for receipt in receipts:
        write_once(export / "receipts" / manifest.session_id /
                   f"receipt_{receipt.anchor_seq:08d}.json", receipt.to_json())
    chain = verify_chain(evidence, manifest)
    verification = verify_receipts(manifest, chain, public, evidence, export)
    recovered = recover_evidence(evidence, anchor_public_key=public_path,
                                 anchor_receipts=export)
    return recovered.status, verification.reason, export
