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
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vmbox.anchor.ledger import AnchorLedger
from vmbox.anchor.receipt_crypto import GENESIS_RECEIPT_HASH, receipt_hash, verify_receipt_signature
from vmbox.canonical import canonical_json
from vmbox.schema import Checkpoint, Receipt

_DOMAIN = b"vmbox-anchor-request-v1\n"
_LIMIT = 65536
_EXPORT_DOMAIN = b"vmbox-anchor-export-v1\n"
_PAGE_LIMIT = 16


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
            if request.get("transport_version") != 1 or type(request.get("auth")) is not str:
                raise ValueError("invalid anchor request")
            if set(request) == {"transport_version", "checkpoint", "auth"}:
                body = {"transport_version": 1, "checkpoint": request["checkpoint"]}
                kind = "checkpoint"
            elif set(request) == {"transport_version", "receipt_page", "auth"}:
                body = {"transport_version": 1, "receipt_page": request["receipt_page"]}
                kind = "receipt_page"
            else:
                raise ValueError("invalid anchor request")
            server = self.server
            if not isinstance(server, _Server):
                raise RuntimeError("invalid anchor server")
            if not hmac.compare_digest(request["auth"], _mac(server.key, body)):
                raise ValueError("anchor authentication failed")
            if kind == "checkpoint":
                checkpoint = Checkpoint.from_dict(request["checkpoint"])
                receipt = server.ledger.accept(checkpoint)
                response = {"transport_version": 1, "receipt": receipt.to_dict()}
            else:
                page = request["receipt_page"]
                if type(page) is not dict or set(page) != {"session_id", "start", "nonce"} \
                        or type(page["start"]) is not int or page["start"] < 0 \
                        or type(page["nonce"]) is not str or len(page["nonce"]) != 32:
                    raise ValueError("invalid receipt page request")
                receipts = server.ledger.session_receipts(page["session_id"])
                state = {"session_id": page["session_id"], "nonce": page["nonce"],
                         "total": len(receipts),
                         "tail_hash": receipt_hash(receipts[-1]) if receipts
                         else GENESIS_RECEIPT_HASH}
                signature = server.ledger.private_key.sign(
                    _EXPORT_DOMAIN + canonical_json(state)).hex()
                response = {"transport_version": 1, "receipt_page": {
                    "state": state, "signature": "ed25519:" + signature,
                    "start": page["start"],
                    "receipts": [r.to_dict() for r in receipts[page["start"]:
                                                                 page["start"] + _PAGE_LIMIT]]}}
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


def fetch_receipt_log(endpoint: str, session_id: str, key: bytes,
                      public_key: Ed25519PublicKey, *, timeout: float = 5) -> list[Receipt]:
    """Fetch an anchor-signed, nonce-bound snapshot of one receipt history.

    Cross-VM operation is unverified until run on both Windows VMs.
    """
    if len(key) < 32 or timeout <= 0:
        raise ValueError("invalid anchor key or timeout")
    receipts: list[Receipt] = []
    expected_state: tuple[int, str] | None = None
    while True:
        nonce = uuid4().hex
        page = {"session_id": session_id, "start": len(receipts), "nonce": nonce}
        body = {"transport_version": 1, "receipt_page": page}
        request = {**body, "auth": _mac(key, body)}
        host, port = _endpoint(endpoint)
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(canonical_json(request) + b"\n")
            with connection.makefile("rb") as stream:
                response = _decode(stream.readline(_LIMIT + 1))
        if set(response) == {"transport_version", "error"}:
            raise ValueError(f"anchor rejected receipt export: {response['error']}")
        if set(response) != {"transport_version", "receipt_page"} \
                or response["transport_version"] != 1:
            raise ValueError("invalid receipt export response")
        chunk = response["receipt_page"]
        if type(chunk) is not dict or set(chunk) != {"state", "signature", "start", "receipts"}:
            raise ValueError("invalid receipt export page")
        state = chunk["state"]
        if type(state) is not dict or set(state) != {"session_id", "nonce", "total", "tail_hash"} \
                or state["session_id"] != session_id or state["nonce"] != nonce \
                or type(state["total"]) is not int or state["total"] < 0 \
                or type(state["tail_hash"]) is not str:
            raise ValueError("invalid receipt export state")
        signature = chunk["signature"]
        if type(signature) is not str or len(signature) != 136 \
                or not signature.startswith("ed25519:") \
                or any(c not in "0123456789abcdef" for c in signature[8:]):
            raise ValueError("invalid receipt export signature")
        try:
            public_key.verify(bytes.fromhex(signature[8:]),
                              _EXPORT_DOMAIN + canonical_json(state))
        except Exception as exc:
            raise ValueError("receipt export signature mismatch") from exc
        snapshot = (state["total"], state["tail_hash"])
        if expected_state is not None and snapshot != expected_state:
            raise ValueError("anchor receipt history changed during export; retry")
        expected_state = snapshot
        if chunk["start"] != len(receipts) or type(chunk["receipts"]) is not list \
                or len(chunk["receipts"]) > _PAGE_LIMIT:
            raise ValueError("invalid receipt export position")
        for item in chunk["receipts"]:
            receipt = Receipt.from_dict(item)
            if receipt.checkpoint.session_id != session_id \
                    or receipt.anchor_seq != len(receipts) \
                    or receipt.prev_receipt_hash != (receipt_hash(receipts[-1]) if receipts
                                                    else GENESIS_RECEIPT_HASH):
                raise ValueError("receipt export chain mismatch")
            verify_receipt_signature(public_key, receipt)
            receipts.append(receipt)
        if len(receipts) > state["total"] or (not chunk["receipts"] and
                                               len(receipts) < state["total"]):
            raise ValueError("receipt export is incomplete")
        if len(receipts) == state["total"]:
            if (receipt_hash(receipts[-1]) if receipts else GENESIS_RECEIPT_HASH) \
                    != state["tail_hash"]:
                raise ValueError("receipt export tail mismatch")
            return receipts
