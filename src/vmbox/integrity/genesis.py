"""Hash-chain genesis from the canonical session manifest."""

from hashlib import sha256

from vmbox.schema import SessionManifest


def manifest_genesis(manifest: SessionManifest) -> bytes:
    """Return H(0), the raw SHA-256 digest of the canonical manifest bytes."""
    return sha256(manifest.to_json()).digest()
