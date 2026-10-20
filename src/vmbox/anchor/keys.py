"""Create anchor-only signing material and a separate shared transport key."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vmbox.anchor.ledger import write_once
from vmbox.anchor.receipt_crypto import public_key_fingerprint


def create_anchor_keys(directory: Path) -> str:
    if directory.exists():
        raise FileExistsError(directory)
    directory.mkdir(parents=True)
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    write_once(directory / "private.pem", private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    write_once(directory / "public.pem", public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    write_once(directory / "auth.key", os.urandom(32))
    return public_key_fingerprint(public)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("anchor private key must be Ed25519")
    return loaded
