"""Freeze canonical ground-truth labels before strategy evaluation."""

import json
import os
from hashlib import sha256
from pathlib import Path

from vmbox.schema import GroundTruthLabel


def freeze_labels(path: Path, labels: GroundTruthLabel) -> str:
    """Write once and return the SHA-256 tag of exact canonical bytes."""
    raw = labels.to_json()
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return "sha256:" + sha256(raw).hexdigest()


def read_labels(path: Path, expected_hash: str | None = None) -> GroundTruthLabel:
    raw = path.read_bytes()
    actual = "sha256:" + sha256(raw).hexdigest()
    if expected_hash is not None and actual != expected_hash:
        raise ValueError("label hash mismatch")
    try:
        data = json.loads(raw.decode("utf-8"))
        labels = GroundTruthLabel.from_dict(data)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("invalid ground-truth labels") from exc
    if labels.to_json() != raw:
        raise ValueError("noncanonical ground-truth labels")
    return labels
