"""Prepare an explicit write-once M8 attempt list from selected run directories."""

import json
import os
from pathlib import Path
from typing import Literal

from vmbox.canonical import canonical_json
from vmbox.schema import EvaluationResult, EvaluationResultV2


def write_inventory(directories: list[Path], attempts_path: Path, roles_path: Path,
                    *, set_role: Literal["tuning", "held_out"],
                    failed: dict[str, str] | None = None) -> None:
    """Role assignment is an explicit caller choice, never inferred from names."""
    if not directories and not failed:
        raise ValueError("inventory needs at least one completed or failed attempt")
    if attempts_path.exists() or roles_path.exists():
        raise FileExistsError("inventory outputs are write-once")
    attempts = []
    roles = {}
    seen = set()
    for directory in directories:
        result_path = directory / "result.json"
        raw = result_path.read_bytes()
        data = json.loads(raw)
        if canonical_json(data) != raw:
            raise ValueError(f"noncanonical result: {result_path}")
        result: EvaluationResult | EvaluationResultV2
        if "result_format_version" in data:
            result = EvaluationResultV2.from_dict(data)
            if result.set_role != set_role:
                raise ValueError(f"v2 set_role mismatch: {result_path}")
        else:
            result = EvaluationResult.from_dict(data)
            roles[result.run_id] = set_role
        if result.run_id in seen:
            raise ValueError("duplicate run_id in inventory")
        seen.add(result.run_id)
        relative = os.path.relpath(result_path, attempts_path.parent)
        if ".." in Path(relative).parts:
            raise ValueError("attempt manifest must be a parent of every result file")
        attempts.append({"run_id": result.run_id,
                         "result_path": Path(relative).as_posix(),
                         "failure_reason": None})
    for run_id, reason in (failed or {}).items():
        if not run_id or not reason.strip() or run_id in seen:
            raise ValueError("invalid failed-run entry")
        attempts.append({"run_id": run_id, "result_path": None,
                         "failure_reason": reason})
    attempts.sort(key=lambda item: str(item["run_id"]))
    attempts_path.parent.mkdir(parents=True, exist_ok=True)
    with attempts_path.open("xb") as stream:
        stream.write(canonical_json({"attempts": attempts}))
        stream.flush()
        os.fsync(stream.fileno())
    if roles:
        with roles_path.open("xb") as stream:
            stream.write(canonical_json(roles))
            stream.flush()
            os.fsync(stream.fileno())
