"""Legacy v1 results require a recorded, hashed set-role decision."""

import json
import re
from hashlib import sha256
from pathlib import Path

import pytest

from vmbox.canonical import canonical_json
from vmbox.eval.result_reader import read_result, read_role_map
from vmbox.schema import EvaluationResultV2


def _legacy() -> dict:
    text = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    return json.loads(re.findall(r"```json\s*(.*?)```", text, re.DOTALL)[-1])


def test_v2_requires_set_role_and_version(tmp_path: Path) -> None:
    data = {**_legacy(), "result_format_version": 2, "set_role": "tuning"}
    assert EvaluationResultV2.from_dict(data).set_role == "tuning"
    with pytest.raises(ValueError):
        EvaluationResultV2.from_dict({key: value for key, value in data.items()
                                      if key != "set_role"})
    with pytest.raises(ValueError):
        EvaluationResultV2.from_dict({**data, "set_role": "other"})
    with pytest.raises(ValueError):
        EvaluationResultV2.from_dict({**data, "result_format_version": 1})
    path = tmp_path / "result.json"
    path.write_bytes(canonical_json(data))
    loaded = read_result(path)
    assert not loaded.legacy and loaded.result.set_role == "tuning"


def test_v1_requires_canonical_explicit_mapping_and_records_hash(tmp_path: Path) -> None:
    old = _legacy()
    path = tmp_path / "result.json"
    original = canonical_json(old)
    path.write_bytes(original)
    with pytest.raises(ValueError, match="explicit set_role mapping"):
        read_result(path)
    mapping = tmp_path / "roles.json"
    mapping_bytes = canonical_json({old["run_id"]: "held_out"})
    mapping.write_bytes(mapping_bytes)
    roles, mapping_hash = read_role_map(mapping)
    loaded = read_result(path, legacy_roles=roles)
    assert loaded.legacy and loaded.result.set_role == "held_out"
    assert path.read_bytes() == original
    assert mapping_hash == "sha256:" + sha256(mapping_bytes).hexdigest()
    assert loaded.file_hash == "sha256:" + sha256(original).hexdigest()
    mapping.write_bytes(b'{ "bad":"tuning" }')
    with pytest.raises(ValueError, match="canonical"):
        read_role_map(mapping)
