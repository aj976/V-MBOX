"""Local verification CLI uses APPFLOW exit codes and names its limits."""

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from vmbox.cli import main
from vmbox.schema import SessionManifest
from vmbox.store.journal import create_journal
from vmbox.store.manifest import write_manifest


def manifest():
    text = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    example = json.loads(re.findall(r"```json\s*(.*?)```", text, re.DOTALL)[1])
    return SessionManifest.from_dict(example)


def test_cli_verify_reports_local_scope_and_incomplete(tmp_path: Path, capsys):
    assert main(["verify", "--evidence", str(tmp_path)]) == 3
    write_manifest(tmp_path / "manifest.json", manifest())
    create_journal(tmp_path / "journal.bin", 2048)
    assert main(["verify", "--evidence", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "anchor: not checked" in output
    (tmp_path / "journal.bin").unlink()
    assert main(["verify", "--evidence", str(tmp_path)]) == 3


def test_offline_verify_cannot_claim_anchor(tmp_path: Path, capsys):
    write_manifest(tmp_path / "manifest.json", replace(manifest(), mode="offline_eval"))
    create_journal(tmp_path / "journal.bin", 2048)
    assert main(["verify", "--evidence", str(tmp_path),
                 "--anchor-pubkey", str(tmp_path / "unused.pub")]) == 0
    output = capsys.readouterr().out
    assert "offline evaluation session, not forensic evidence" in output
    assert "integrity level: chained" in output
    assert "anchored" not in output


def test_record_requires_anchor_config(capsys):
    with pytest.raises(SystemExit):
        main(["record"])
    assert "live record requires" in capsys.readouterr().err
