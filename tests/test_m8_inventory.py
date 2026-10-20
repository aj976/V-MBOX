"""Inventory records every selected run and explicit legacy role without inference."""

import json
from pathlib import Path

import pytest
from test_m8_aggregate import _write_inputs

from vmbox.eval.aggregate import build_aggregate
from vmbox.eval.inventory import write_inventory


def test_inventory_records_legacy_roles_and_failure(tmp_path: Path) -> None:
    source, _ = _write_inputs(tmp_path, legacy=True)
    data = json.loads(source.read_bytes())
    directories = []
    for item in data["attempts"]:
        if item["result_path"] is None:
            continue
        directory = tmp_path / "runs" / item["run_id"]
        directory.mkdir(parents=True)
        (directory / "result.json").write_bytes(
            (tmp_path / item["result_path"]).read_bytes())
        directories.append(directory)
    attempts = tmp_path / "runs" / "attempts.json"
    roles = tmp_path / "runs" / "roles.json"
    write_inventory(directories, attempts, roles, set_role="tuning",
                    failed={"failed-extra": "synthetic interrupted attempt"})
    assert len(json.loads(attempts.read_bytes())["attempts"]) == 7
    assert len(json.loads(roles.read_bytes())) == 6
    report = build_aggregate(attempts, role_map_path=roles, generated_at=1)
    assert report.runs_failed == 1 and report.legacy_role_map_hash is not None
    with pytest.raises(FileExistsError):
        write_inventory(directories, attempts, roles, set_role="tuning")


def test_inventory_rejects_wrong_v2_role(tmp_path: Path) -> None:
    source, _ = _write_inputs(tmp_path)
    first = json.loads(source.read_bytes())["attempts"][0]
    directory = tmp_path / "runs" / "one"
    directory.mkdir(parents=True)
    (directory / "result.json").write_bytes((tmp_path / first["result_path"]).read_bytes())
    with pytest.raises(ValueError, match="set_role mismatch"):
        write_inventory([directory], tmp_path / "runs" / "attempts.json",
                        tmp_path / "runs" / "roles.json", set_role="held_out")
