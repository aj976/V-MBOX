"""Read v1/v2 evaluation results without rewriting persisted v1 artifacts."""

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from vmbox.canonical import canonical_json
from vmbox.schema import EvaluationResult, EvaluationResultV2

SetRole = Literal["tuning", "held_out"]
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class LoadedResult:
    result: EvaluationResultV2
    file_hash: str
    legacy: bool


def read_role_map(path: Path) -> tuple[dict[str, SetRole], str]:
    """The mapping file is canonical JSON and part of aggregate provenance."""
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid legacy role mapping") from exc
    if type(data) is not dict or not data or any(
        type(key) is not str or not key or value not in ("tuning", "held_out")
        for key, value in data.items()
    ) or canonical_json(data) != raw:
        raise ValueError("legacy role mapping must be canonical run_id-to-role JSON")
    return data, "sha256:" + sha256(raw).hexdigest()


def read_result(path: Path, *, legacy_roles: dict[str, SetRole] | None = None
                ) -> LoadedResult:
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid result JSON: {path}") from exc
    if type(data) is not dict or canonical_json(data) != raw:
        raise ValueError(f"result is not canonical JSON: {path}")
    if "result_format_version" in data:
        result = EvaluationResultV2.from_dict(data)
        legacy = False
    else:
        old = EvaluationResult.from_dict(data)
        if legacy_roles is None or old.run_id not in legacy_roles:
            raise ValueError(f"legacy v1 run {old.run_id} needs an explicit set_role mapping")
        result = EvaluationResultV2.from_dict({
            **old.to_dict(), "result_format_version": 2,
            "set_role": legacy_roles[old.run_id],
        })
        legacy = True
    for value in (result.trace_hash, result.label_hash, result.config_hash):
        if _HASH.fullmatch(value) is None:
            raise ValueError("result has invalid provenance hash")
    return LoadedResult(result, "sha256:" + sha256(raw).hexdigest(), legacy)
