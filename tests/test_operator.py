"""Operator shortcuts preserve the explicit CLI and write-once behavior."""

from pathlib import Path
from uuid import uuid4

import pytest

from vmbox.cli import main
from vmbox.operator import (
    Profile,
    default_export,
    default_report,
    latest_session,
    load_profile,
    remember_session,
    save_profile,
)
from vmbox.schema import AnchorInfo, SessionManifest
from vmbox.store.manifest import write_manifest


def test_profile_round_trip_and_write_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VMBOX_PROFILE_DIR", str(tmp_path / "profiles"))
    profile = Profile("demo", "monitored", tmp_path, "abc123", "127.0.0.1:8765")
    save_profile(profile)
    assert load_profile("demo", "monitored") == profile
    with pytest.raises(FileExistsError):
        save_profile(profile)
    with pytest.raises(ValueError, match="expected anchor"):
        load_profile("demo", "anchor")
    assert default_export(tmp_path / "live_1") == tmp_path / "anchor_export_live_1"
    assert default_report(tmp_path / "live_1") == tmp_path / "report_live_1"


def _live_session(path: Path, endpoint: str) -> None:
    path.mkdir()
    write_manifest(path / "manifest.json", SessionManifest(
        1, "live", str(uuid4()), str(uuid4()), "test-host", 1, "test", "sha256:" + "1" * 64,
        "context_aware", 12 * 1048576, 8 * 1048576,
        AnchorInfo(endpoint, "sha256:" + "2" * 64)))


def test_latest_session_remembers_and_discovers_previous_run(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VMBOX_PROFILE_DIR", str(tmp_path / "profiles"))
    profile = Profile("demo", "monitored", tmp_path, "abc123", "127.0.0.1:8765")
    old = tmp_path / "live_old"
    new = tmp_path / "live_new"
    _live_session(old, profile.endpoint)
    _live_session(new, profile.endpoint)
    assert latest_session(profile) == new
    remember_session(profile, old)
    assert latest_session(profile) == old
    remember_session(profile, new)
    assert latest_session(profile) == new
    with pytest.raises(ValueError, match="does not match"):
        remember_session(profile, tmp_path / "not_a_live_session")


def test_record_profile_supplies_operator_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                  capsys: pytest.CaptureFixture[str]) -> None:
    from vmbox.record import command

    monkeypatch.setenv("VMBOX_PROFILE_DIR", str(tmp_path / "profiles"))
    save_profile(Profile("demo", "monitored", tmp_path, "abc123", "127.0.0.1:8765"))
    captured = {}

    def fake_record(**kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return "sha256:" + "a" * 64, 1, 0, 0

    monkeypatch.setattr(command, "record_sysmon", fake_record)
    assert main(["record", "--duration", "60", "--profile", "demo"]) == 0
    assert captured["budget_bytes"] == 12 * 1048576
    assert captured["anchor_endpoint"] == "127.0.0.1:8765"
    assert captured["output"].parent == tmp_path
    assert "evidence:" in capsys.readouterr().out


def test_report_open_uses_created_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

    opened = []
    monkeypatch.setattr("vmbox.cli.webbrowser.open", lambda url: opened.append(url) or True)
    # A missing evidence directory still returns incomplete, without opening a browser.
    assert main(["report", "--evidence", str(tmp_path / "missing"), "--open"]) == 3
    assert opened == []

    from types import SimpleNamespace

    from vmbox.reconstruct import report
    from vmbox.recover import evidence

    monkeypatch.setattr(evidence, "recover_evidence", lambda *args, **kwargs:
                        SimpleNamespace(status="ok"))
    monkeypatch.setattr("vmbox.cli.recover_evidence", lambda *args, **kwargs:
                        SimpleNamespace(status="ok"))
    monkeypatch.setattr(report, "build_report", lambda *args, **kwargs:
                        SimpleNamespace(content_hash="sha256:" + "a" * 64))
    expected_html = tmp_path / "report_missing" / "report.html"
    monkeypatch.setattr(report, "write_report", lambda *args, **kwargs:
                        (tmp_path / "report_missing" / "report.json", expected_html))
    assert main(["report", "--evidence", str(tmp_path / "missing"), "--open"]) == 0
    assert opened == [expected_html.resolve().as_uri()]
