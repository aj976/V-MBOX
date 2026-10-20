"""Synthetic recorder tests; Sysmon/second-VM behavior is unverified."""

import socket
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vmbox.anchor.client import sync_receipts
from vmbox.anchor.ledger import AnchorLedger
from vmbox.anchor.transport import serve_anchor
from vmbox.collect.capture import make_sysmon_header
from vmbox.collect.trace import TraceRecord
from vmbox.eval.policies import PolicyStrategy
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.receipts import verify_receipts
from vmbox.record.live import LiveRecorder


def _records() -> list[TraceRecord]:
    return [
        TraceRecord("collector", "COLLECTOR_START", 10, {}),
        TraceRecord("sysmon", "PROC_START", 11,
                    {"ProcessId": "42", "ParentProcessId": "1", "Image": "python.exe",
                     "CommandLineHash": "sha256:" + "a" * 64}),
        TraceRecord("collector", "COLLECTOR_STOP", 12, {}),
    ]


def test_live_record_seals_and_syncs_receipts(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    anchor = serve_anchor("127.0.0.1:0", AnchorLedger(tmp_path / "anchor", private),
                          b"k" * 32)
    thread = threading.Thread(target=anchor.serve_forever, daemon=True)
    thread.start()
    try:
        header = make_sysmon_header(b"xml", "boot", "test", 16)
        root = tmp_path / "evidence"
        recorder = LiveRecorder(
            root, header, PolicyStrategy("fifo_ring"), budget_bytes=100000,
            journal_bytes=8192, segment_events=2,
            anchor_endpoint=f"127.0.0.1:{anchor.server_address[1]}",
            anchor_public_key=private.public_key(), anchor_auth_key=b"k" * 32,
            host="lab-host",
        )
        for record in _records():
            recorder.on_record(record)
        result = recorder.finish()
        assert result.pending_segments == 0
        chain = verify_chain(root, recorder.manifest)
        assert chain.status == "ok" and len(chain.entries) == 2
        receipts = verify_receipts(recorder.manifest, chain, private.public_key(), root,
                                   tmp_path / "anchor")
        assert receipts.status == "ok"
    finally:
        anchor.shutdown()
        anchor.server_close()
        thread.join(timeout=2)


def test_anchor_outage_keeps_chained_segments_for_later_sync(tmp_path: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    private = Ed25519PrivateKey.generate()
    header = make_sysmon_header(b"xml", "boot", "test", 16)
    root = tmp_path / "evidence"
    recorder = LiveRecorder(
        root, header, PolicyStrategy("fifo_ring"), budget_bytes=100000,
        journal_bytes=8192, segment_events=2,
        anchor_endpoint=f"127.0.0.1:{port}",
        anchor_public_key=private.public_key(), anchor_auth_key=b"k" * 32,
        host="lab-host", anchor_timeout=0.2,
    )
    for record in _records():
        recorder.on_record(record)
    assert recorder.finish().pending_segments == 2
    assert verify_chain(root, recorder.manifest).status == "ok"
    anchor = serve_anchor(f"127.0.0.1:{port}", AnchorLedger(tmp_path / "anchor", private),
                          b"k" * 32)
    thread = threading.Thread(target=anchor.serve_forever, daemon=True)
    thread.start()
    try:
        synced = sync_receipts(root, recorder.manifest, private.public_key(), b"k" * 32)
        assert synced.pending_segments == 0 and synced.anchored_segments == 2
    finally:
        anchor.shutdown()
        anchor.server_close()
        thread.join(timeout=2)
