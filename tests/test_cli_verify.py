"""Local verification CLI uses APPFLOW exit codes and names its limits."""

import json
import os
import re
import subprocess
import sys
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


def test_offline_verify_needs_no_anchor_crypto_dependency(tmp_path: Path):
    offline = replace(manifest(), mode="offline_eval", anchor=None)
    write_manifest(tmp_path / "manifest.json", offline)
    create_journal(tmp_path / "journal.bin", 2048)
    source_root = Path(__file__).resolve().parents[1] / "src"
    result = subprocess.run(
        [sys.executable, "-S", "-m", "vmbox.cli", "verify", "--evidence", str(tmp_path)],
        env={**os.environ, "PYTHONPATH": str(source_root)},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "integrity level: chained" in result.stdout
