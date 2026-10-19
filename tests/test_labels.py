"""M5 label freezing is independent of live telemetry choices."""

import json
import re
from pathlib import Path

import pytest

from vmbox.eval.labels import freeze_labels, read_labels
from vmbox.schema import GroundTruthLabel


def example():
    schema = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    return GroundTruthLabel.from_dict(json.loads(
        re.findall(r"```json\s*(.*?)```", schema, re.DOTALL)[6]))


def test_labels_are_canonical_frozen_and_hash_checked(tmp_path: Path):
    path = tmp_path / "labels.json"
    labels = example()
    digest = freeze_labels(path, labels)
    assert read_labels(path, digest) == labels
    with pytest.raises(FileExistsError):
        freeze_labels(path, labels)
    damaged = bytearray(path.read_bytes())
    damaged[10] ^= 1
    path.write_bytes(damaged)
    with pytest.raises(ValueError, match="hash mismatch"):
        read_labels(path, digest)
