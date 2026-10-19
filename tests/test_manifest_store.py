"""Manifest bytes are stable genesis input and cannot be overwritten."""

import json
import re
from pathlib import Path

import pytest

from vmbox.integrity.genesis import manifest_genesis
from vmbox.schema import SessionManifest
from vmbox.store.manifest import read_manifest, write_manifest


def manifest():
    text = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    example = json.loads(re.findall(r"```json\s*(.*?)```", text, re.DOTALL)[1])
    return SessionManifest.from_dict(example)


def test_manifest_write_once_roundtrip_and_tamper(tmp_path: Path):
    path = tmp_path / "manifest.json"
    model = manifest()
    write_manifest(path, model)
    assert read_manifest(path) == model
    assert path.read_bytes() == model.to_json()
    assert len(manifest_genesis(read_manifest(path))) == 32
    with pytest.raises(FileExistsError):
        write_manifest(path, model)
    damaged = bytearray(path.read_bytes())
    damaged[10] ^= 1
    path.write_bytes(damaged)
    with pytest.raises(ValueError):
        read_manifest(path)
