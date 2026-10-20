"""M7 report tests use synthetic evidence; no values here are VM measurements."""

import json
from hashlib import sha256
from pathlib import Path

import pytest
from test_recovery import _unbounded

from vmbox.canonical import canonical_json
from vmbox.cli import main
from vmbox.reconstruct.report import build_report, render_report_html, write_report
from vmbox.recover.evidence import recover_evidence
from vmbox.schema import Report


def _rehash(data: dict) -> dict:
    content = {key: value for key, value in data.items()
               if key not in {"generated_at", "content_hash"}}
    return {**data, "content_hash": "sha256:" + sha256(canonical_json(content)).hexdigest()}


def test_report_hash_excludes_generation_time_and_is_write_once(tmp_path: Path) -> None:
    evidence = _unbounded(tmp_path)
    recovered = recover_evidence(evidence)
    first = build_report(evidence, recovered, generated_at=1)
    second = build_report(evidence, recovered, generated_at=2)
    assert first.content_hash == second.content_hash
    assert first.to_json() != second.to_json()
    json_path, html_path = write_report(tmp_path / "out", first)
    assert Report.from_dict(json.loads(json_path.read_bytes())) == first
    assert first.content_hash in html_path.read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_report(tmp_path / "out", second)
    assert "offline evaluation session, not forensic evidence" in html_path.read_text(
        encoding="utf-8")
    assert "chained" in html_path.read_text(encoding="utf-8")


def test_report_cli_writes_valid_pair(tmp_path: Path) -> None:
    evidence = _unbounded(tmp_path)
    output = tmp_path / "cli-report"
    assert main(["report", "--evidence", str(evidence), "--out", str(output)]) == 0
    report = Report.from_dict(json.loads((output / "report.json").read_bytes()))
    assert report.content_hash in (output / "report.html").read_text(encoding="utf-8")
    assert report.verify_result["exit_code"] == 0


def test_empty_limitations_and_changed_content_rejected(tmp_path: Path) -> None:
    evidence = _unbounded(tmp_path)
    report = build_report(evidence, recover_evidence(evidence), generated_at=1)
    data = report.to_dict()
    data["limitations"] = []
    with pytest.raises(ValueError, match="limitations"):
        Report.from_dict(_rehash(data))
    data = report.to_dict()
    data["session"]["host"] = "changed"
    with pytest.raises(ValueError, match="hash"):
        Report.from_dict(data)


def test_tampered_fixture_preserves_verify_exit_two(tmp_path: Path) -> None:
    evidence = _unbounded(tmp_path)
    segment = next(evidence.glob("seg_*.vseg"))
    with segment.open("r+b") as stream:
        stream.seek(64)
        original = stream.read(1)
        stream.seek(64)
        stream.write(bytes([original[0] ^ 1]))
    recovered = recover_evidence(evidence)
    assert recovered.status == "tampered"
    report = build_report(evidence, recovered, generated_at=1)
    assert report.verify_result["exit_code"] == 2
    assert "tampered" in report.verify_result["output"]
    assert report.recovery_summary["status"] == "tampered"
    assert report.integrity_counts["tampered"] == 1
    assert main(["report", "--evidence", str(evidence), "--out",
                 str(tmp_path / "tampered-report")]) == 2


def test_html_escapes_untrusted_fields(tmp_path: Path) -> None:
    evidence = _unbounded(tmp_path)
    report = build_report(evidence, recover_evidence(evidence), generated_at=1)
    data = report.to_dict()
    payload = '<script>alert(1)</script><img src=x onerror=alert(2)></style>'
    data["event_details"][0]["image"] = payload
    report_path = tmp_path / "report.json"
    report_path.write_bytes(canonical_json(_rehash(data)))
    html = render_report_html(report_path)
    assert "&lt;script&gt;" in html
    assert "&lt;/style&gt;" in html
    assert payload not in html
    assert "<img src=x" not in html
    assert html.count("<script") == 1
    assert "alert(1)" not in html.split("<script>", 1)[1]


def test_raw_command_line_is_marked_and_escaped(tmp_path: Path) -> None:
    evidence = _unbounded(tmp_path)
    report = build_report(evidence, recover_evidence(evidence), generated_at=1)
    data = report.to_dict()
    data["event_details"][0]["cmdline"] = '<img src=x onerror="bad()">'
    data["limitations"].append("Contains raw command lines, do not share.")
    report_path = tmp_path / "raw-report.json"
    report_path.write_bytes(canonical_json(_rehash(data)))
    html = render_report_html(report_path)
    assert "contains raw command lines, do not share" in html
    assert "&lt;img src=x onerror=" in html
    assert "<img src=x" not in html


def test_authored_report_language_avoids_forbidden_claims(tmp_path: Path) -> None:
    evidence = _unbounded(tmp_path)
    report = build_report(evidence, recover_evidence(evidence), generated_at=1)
    authored = canonical_json({"limitations": report.limitations,
                               "reconstruction_limitations": report.reconstruction.limitations,
                               "html": render_report_html(_write_json(tmp_path, report))}).decode()
    for forbidden in ("malicious", "proves", "confirms exfiltration",
                      "attacker intent", "attribution"):
        assert forbidden not in authored.lower()


def _write_json(tmp_path: Path, report: Report) -> Path:
    path = tmp_path / "language-report.json"
    path.write_bytes(report.to_json())
    return path
