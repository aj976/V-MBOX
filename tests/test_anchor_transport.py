"""Loopback protocol tests; second-VM transport remains unverified."""

import socket
import threading
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vmbox.anchor.keys import create_anchor_keys, load_private_key
from vmbox.anchor.ledger import AnchorLedger
from vmbox.anchor.receipt_crypto import load_public_key, public_key_fingerprint
from vmbox.anchor.transport import send_checkpoint, serve_anchor
from vmbox.schema import Checkpoint


def test_checkpoint_round_trip_and_idempotence(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    server = serve_anchor("127.0.0.1:0", AnchorLedger(tmp_path, private_key),
                          b"a" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"127.0.0.1:{server.server_address[1]}"
        checkpoint = Checkpoint(str(uuid4()), 0, "sha256:" + "1" * 64, 9, 10)
        first = send_checkpoint(endpoint, checkpoint, b"a" * 32,
                                private_key.public_key())
        second = send_checkpoint(endpoint, checkpoint, b"a" * 32,
                                 private_key.public_key())
        assert first == second
        assert len(list((tmp_path / "receipts" / checkpoint.session_id).glob("*.json"))) == 1
        with pytest.raises(ValueError, match="authentication"):
            send_checkpoint(endpoint, checkpoint, b"b" * 32, private_key.public_key())
        with pytest.raises(ValueError, match="signature"):
            send_checkpoint(endpoint, checkpoint, b"a" * 32,
                            Ed25519PrivateKey.generate().public_key())
        with pytest.raises(ValueError, match="conflicting segment hash"):
            send_checkpoint(endpoint, Checkpoint(checkpoint.session_id, 0,
                            "sha256:" + "2" * 64, 9, 10), b"a" * 32,
                            private_key.public_key())
        assert len(list((tmp_path / "equivocations" / checkpoint.session_id).glob("*.json"))) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_rejects_malformed_request(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    server = serve_anchor("127.0.0.1:0", AnchorLedger(tmp_path, private_key),
                          b"a" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address) as connection:
            connection.sendall(b'{"transport_version":1}\n')
            assert b"error" in connection.recv(4096)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_key_generation_is_write_once(tmp_path: Path) -> None:
    root = tmp_path / "keys"
    fingerprint = create_anchor_keys(root)
    assert fingerprint == public_key_fingerprint(load_public_key(root / "public.pem"))
    assert load_private_key(root / "private.pem").public_key().public_bytes_raw() \
        == load_public_key(root / "public.pem").public_bytes_raw()
    assert len((root / "auth.key").read_bytes()) == 32
    with pytest.raises(FileExistsError):
        create_anchor_keys(root)
