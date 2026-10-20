"""Bounded canonical checkpoint transport for an isolated lab network.

Unverified until run on the second Windows VM. The shared key authenticates
checkpoint requests; signed receipts authenticate the anchor to the host.
This protocol does not provide confidentiality and must not face the Internet.
"""

import hmac
import json
import socket
import socketserver
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vmbox.anchor.ledger import AnchorLedger
from vmbox.anchor.receipt_crypto import verify_receipt_signature
from vmbox.canonical import canonical_json
from vmbox.schema import Checkpoint, Receipt

_DOMAIN = b"vmbox-anchor-request-v1\n"
_LIMIT = 65536


def _mac(key: bytes, body: dict[str, Any]) -> str:
    return hmac.new(key, _DOMAIN + canonical_json(body), sha256).hexdigest()


def _decode(line: bytes) -> dict[str, Any]:
    if len(line) > _LIMIT or not line.endswith(b"\n"):
        raise ValueError("anchor message is oversized or incomplete")
    try:
        value = json.loads(line[:-1].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid anchor message") from exc
    if type(value) is not dict or canonical_json(value) + b"\n" != line:
        raise ValueError("noncanonical anchor message")
    return value


def _endpoint(value: str, *, allow_zero: bool = False) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("anchor endpoint must be host:port")
    port = int(port_text)
    if not ((allow_zero and port == 0) or 1 <= port <= 65535):
        raise ValueError("anchor port is out of range")
    return host, port


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, endpoint: tuple[str, int], ledger: AnchorLedger, key: bytes):
        self.ledger = ledger
        self.key = key
        super().__init__(endpoint, _Handler)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.connection.settimeout(5)
        try:
            request = _decode(self.rfile.readline(_LIMIT + 1))
            if set(request) != {"transport_version", "checkpoint", "auth"} \
                    or request["transport_version"] != 1 \
                    or type(request["auth"]) is not str:
                raise ValueError("invalid checkpoint request")
            body = {"transport_version": 1, "checkpoint": request["checkpoint"]}
            server = self.server
            if not isinstance(server, _Server):
                raise RuntimeError("invalid anchor server")
            if not hmac.compare_digest(request["auth"], _mac(server.key, body)):
                raise ValueError("checkpoint authentication failed")
            checkpoint = Checkpoint.from_dict(request["checkpoint"])
            receipt = server.ledger.accept(checkpoint)
            response = {"transport_version": 1, "receipt": receipt.to_dict()}
        except (OSError, ValueError, TypeError) as exc:
            response = {"transport_version": 1, "error": str(exc)}
        self.wfile.write(canonical_json(response) + b"\n")


def serve_anchor(endpoint: str, ledger: AnchorLedger, key: bytes) -> _Server:
    """Return a server so callers can serve_forever or shut it down in tests."""
    if len(key) < 32:
        raise ValueError("anchor auth key must contain at least 32 bytes")
    return _Server(_endpoint(endpoint, allow_zero=True), ledger, key)


def send_checkpoint(endpoint: str, checkpoint: Checkpoint, key: bytes,
                    public_key: Ed25519PublicKey, *, timeout: float = 5) -> Receipt:
    if len(key) < 32 or timeout <= 0:
        raise ValueError("invalid anchor key or timeout")
    body = {"transport_version": 1, "checkpoint": checkpoint.to_dict()}
    request = {**body, "auth": _mac(key, body)}
    host, port = _endpoint(endpoint)
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(canonical_json(request) + b"\n")
        with connection.makefile("rb") as stream:
            response = _decode(stream.readline(_LIMIT + 1))
    if response.get("transport_version") != 1:
        raise ValueError("invalid anchor response version")
    if set(response) == {"transport_version", "error"}:
        raise ValueError(f"anchor rejected checkpoint: {response['error']}")
    if set(response) != {"transport_version", "receipt"}:
        raise ValueError("invalid anchor response")
    receipt = Receipt.from_dict(response["receipt"])
    if receipt.checkpoint != checkpoint:
        raise ValueError("anchor receipt checkpoint mismatch")
    verify_receipt_signature(public_key, receipt)
    return receipt


def read_auth_key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) < 32:
        raise ValueError("anchor auth key must contain at least 32 bytes")
    return key
