"""Write-once canonical session manifest used as chain genesis."""

import json
import os
from pathlib import Path

from vmbox.schema import SessionManifest


def write_manifest(path: Path, manifest: SessionManifest) -> None:
    with path.open("xb") as stream:
        stream.write(manifest.to_json())
        stream.flush()
        os.fsync(stream.fileno())


def read_manifest(path: Path) -> SessionManifest:
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
        manifest = SessionManifest.from_dict(data)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("invalid session manifest") from exc
    if manifest.to_json() != raw:
        raise ValueError("noncanonical session manifest")
    return manifest
