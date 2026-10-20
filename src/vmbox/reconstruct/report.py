"""Deterministic report content and inert, self-contained HTML rendering."""

import contextlib
import io
import json
import os
import platform
import time
from hashlib import sha256
from html import escape
from importlib.metadata import version
from pathlib import Path
from typing import Any

from vmbox.canonical import canonical_json
from vmbox.reconstruct.build import build_reconstruction
from vmbox.recover.evidence import RecoveryResult
from vmbox.schema import Report


def _hash_inputs(directory: Path) -> list[dict[str, str]]:
    files = [directory / "manifest.json", directory / "journal.bin"]
    files.extend(directory.glob("seg_*.vseg"))
    files.extend(directory.glob("seg_*.tomb"))
    files.extend((directory / "receipts").rglob("*.json") if
                 (directory / "receipts").exists() else ())
    return [{"path": path.relative_to(directory).as_posix(),
             "sha256": "sha256:" + sha256(path.read_bytes()).hexdigest()}
            for path in sorted(files) if path.is_file()]


def build_report(directory: Path, recovered: RecoveryResult, *,
                 anchor_public_key: Path | None = None,
                 anchor_receipts: Path | None = None,
                 generated_at: int | None = None) -> Report:
    """Use the CLI's actual verification outcome and existing recovery result."""
    from vmbox.cli import main

    arguments = ["verify", "--evidence", str(directory)]
    if anchor_public_key is not None:
        arguments.extend(("--anchor-pubkey", str(anchor_public_key)))
    if anchor_receipts is not None:
        arguments.extend(("--anchor-receipts", str(anchor_receipts)))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exit_code = main(arguments)
    reconstruction = build_reconstruction(recovered)
    counts = {key: 0 for key in ("anchored", "chained", "journal_only",
                                "unverified", "tampered")}
    for item in reconstruction.timeline:
        counts[item.integrity] += 1
    if recovered.status == "tampered":
        counts["tampered"] = 1
    limitations = list(reconstruction.limitations)
    limitations.append("Memory events in this configuration are collector proxies only.")
    if counts["chained"] and not counts["anchored"]:
        limitations.append("Chained records have no independently confirmed anchor receipt.")
    if recovered.manifest.mode == "live" and "not checked" in recovered.receipt_status:
        limitations.append("Anchor state was not checked; a receipt outage cannot be ruled out.")
    if recovered.status == "tampered":
        limitations.append("Integrity verification failed; affected records are excluded.")
    raw_cmdline = any(item.event.process is not None and
                      item.event.process.cmdline is not None for item in recovered.events)
    if raw_cmdline:
        limitations.append("Contains raw command lines, do not share.")
    events = []
    for recovered_event in recovered.events:
        event = recovered_event.event
        process = event.process
        events.append({
            "event_id": event.event_id, "seq": event.seq, "pid": event.pid,
            "event_type": event.event_type,
            "image": process.image if process is not None else None,
            "cmdline_hash": process.cmdline_hash if process is not None else None,
            "cmdline": process.cmdline if process is not None and raw_cmdline else None,
        })
    try:
        package_version = version("vmbox")
    except Exception:
        package_version = None
    manifest = recovered.manifest
    content: dict[str, Any] = {
        "report_format_version": 1,
        "tool_versions": {"python": platform.python_version(), "vmbox": package_version},
        "session": {"host": manifest.host, "boot_id": manifest.boot_id,
                    "session_id": manifest.session_id, "mode": manifest.mode,
                    "strategy": manifest.strategy, "budget_bytes": manifest.budget_bytes,
                    "collector_version": manifest.collector_version,
                    "pubkey_fingerprint": (manifest.anchor.pubkey_fingerprint
                                            if manifest.anchor is not None else None)},
        "evidence_identity": {"chain_head_hash": recovered.chain_head_hash,
                              "segment_count": recovered.segment_count,
                              "tombstone_count": recovered.tombstones,
                              "hash_inputs": _hash_inputs(directory)},
        "verify_result": {"output": output.getvalue(), "exit_code": exit_code},
        "recovery_summary": {"status": recovered.status,
                             "chain_status": recovered.chain_status,
                             "journal_status": recovered.journal_status,
                             "receipt_status": recovered.receipt_status,
                             "recovered_events": len(recovered.events),
                             "journal_evicted_frames": recovered.journal_evicted_frames},
        "integrity_counts": counts, "reconstruction": reconstruction.to_dict(),
        "event_details": events, "limitations": limitations,
    }
    content_hash = "sha256:" + sha256(canonical_json(content)).hexdigest()
    return Report.from_dict({**content, "generated_at": (
        time.time_ns() if generated_at is None else generated_at),
                             "content_hash": content_hash})


def render_report_html(report_path: Path) -> str:
    """Render only validated report.json; all event fields become escaped text."""
    report = Report.from_dict(json.loads(report_path.read_bytes()))
    details = {item["event_id"]: item for item in report.event_details}
    html: list[str] = [
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">",
        "<title>V-MBOX report</title>",
        "<style>body{font:16px sans-serif;max-width:90rem;margin:auto;padding:1rem;"
        "color:#111;background:#fff}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #777;padding:.4rem;text-align:left;vertical-align:top}"
        ".inferred{border-left:4px solid #4065a0;padding-left:.5rem}"
        ".failure{color:#a00;font-weight:bold}.banner{border:2px solid #111;padding:.7rem}"
        "</style><main><h1>V-MBOX evidence report</h1>",
        f"<p>Content hash: {escape(report.content_hash)}</p>",
    ]
    if report.session["mode"] == "offline_eval":
        html.append("<p class=\"banner\">offline evaluation session, not forensic evidence</p>")
    html.append("<h2>Session</h2><dl>")
    for key, value in report.session.items():
        html.append(f"<dt>{escape(key)}</dt><dd>{escape(str(value))}</dd>")
    html.append("</dl><h2>Evidence status</h2>")
    status = str(report.recovery_summary["status"])
    class_name = "failure" if status == "tampered" else ""
    html.append(f"<p class=\"{class_name}\">{escape(status)}</p>")
    html.append("<ul>")
    for key, count in report.integrity_counts.items():
        html.append(f"<li>{escape(key)}: {count}</li>")
    html.append(f"<li>tombstones: {report.evidence_identity['tombstone_count']}</li></ul>")
    html.append(f"<p>Verification exit code: {report.verify_result['exit_code']}</p><pre>"
                f"{escape(str(report.verify_result['output']))}</pre>")
    html.append("<h2>Gaps</h2><ul>")
    for gap in report.reconstruction.gaps:
        seq = "unknown" if gap.seq_range is None else "..".join(map(str, gap.seq_range))
        ts = "unknown" if gap.ts_range_ns is None else "..".join(map(str, gap.ts_range_ns))
        html.append(f"<li>{escape(gap.kind)} ({escape(gap.reason)}): seq {escape(seq)}, "
                    f"ts_ns {escape(ts)}</li>")
    show_raw_cmdline = any(event["cmdline"] is not None for event in report.event_details)
    if show_raw_cmdline:
        html.append("<p class=\"banner\">contains raw command lines, do not share</p>")
    html.append("</ul><h2>Timeline</h2><label>PID <input id=\"pid-filter\" "
                "type=\"text\"></label> <label>Type <input id=\"type-filter\" "
                "type=\"text\"></label><table id=\"timeline\"><thead><tr>"
                "<th>Seq</th><th>Timestamp ns</th>"
                "<th>PID</th><th>Type</th><th>Image</th><th>Command line hash</th>")
    if show_raw_cmdline:
        html.append("<th>Raw command line</th>")
    html.append("<th>Integrity</th></tr></thead><tbody>")
    for timeline_item in report.reconstruction.timeline:
        event = details[timeline_item.ref]
        values = [event["seq"], timeline_item.ts_ns, event["pid"], event["event_type"],
                  event["image"], event["cmdline_hash"]]
        if show_raw_cmdline:
            values.append(event["cmdline"])
        values.append(timeline_item.integrity)
        cells = "".join(
            f"<td>{escape('unknown' if value is None else str(value))}</td>"
            for value in values
        )
        html.append("<tr>" + cells + "</tr>")
    html.append("</tbody></table><h2>Process and connection relations</h2><ul>")
    for relation in report.reconstruction.relations:
        marker = " class=\"inferred\"" if relation.provenance == "inferred" else ""
        html.append(f"<li{marker}><abbr title=\"{escape(relation.basis, quote=True)}\">"
                    f"{escape(relation.type)}</abbr>: {escape(relation.from_)} → "
                    f"{escape(relation.to)}; {escape(relation.provenance)}; "
                    f"{escape(relation.basis)}</li>")
    html.append("</ul><h2>Limitations</h2><ul>")
    for limitation in report.limitations:
        html.append(f"<li>{escape(limitation)}</li>")
    html.append("</ul></main><script>"  # Static filter logic; no event data enters script text.
                "const rows=[...document.querySelectorAll('#timeline tbody tr')];"
                "const pid=document.getElementById('pid-filter');"
                "const type=document.getElementById('type-filter');"
                "function filterRows(){for(const row of rows){"
                "row.hidden=!(row.cells[2].textContent.includes(pid.value.trim())&&"
                "row.cells[3].textContent.toLowerCase().includes(type.value.trim().toLowerCase()))"
                "}}pid.addEventListener('input',filterRows);"
                "type.addEventListener('input',filterRows);"
                "</script></html>")
    return "".join(html)


def write_report(directory: Path, report: Report) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "report.json"
    html_path = directory / "report.html"
    with json_path.open("xb") as stream:
        stream.write(report.to_json())
        stream.flush()
        os.fsync(stream.fileno())
    rendered = render_report_html(json_path)
    with html_path.open("x", encoding="utf-8") as stream:
        stream.write(rendered)
        stream.flush()
        os.fsync(stream.fileno())
    return json_path, html_path
