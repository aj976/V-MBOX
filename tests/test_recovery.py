"""M7 recovery checks use synthetic evidence, not VM measurements."""

import json
from pathlib import Path

from test_eval_harness import _inputs, _versions

from vmbox.eval.harness import run_evaluation
from vmbox.eval.policies import PolicyStrategy
from vmbox.eval.strategy import UnboundedStrategy
from vmbox.reconstruct.build import build_reconstruction
from vmbox.recover.evidence import recover_evidence
from vmbox.schema import Reconstruction
from vmbox.store.journal import recover_journal


def _unbounded(tmp_path: Path) -> Path:
    trace, labels = _inputs(tmp_path)
    output = tmp_path / "unbounded"
    run_evaluation(
        trace, labels, output, strategy=UnboundedStrategy(), journal_bytes=2048,
        budget_bytes=None, unbounded_bytes_retained=None,
        git_commit="a" * 40, git_dirty=False, tool_versions=_versions(), set_role="tuning",
    )
    return output


def test_recovery_prefers_sealed_copy_and_marks_offline_limit(tmp_path: Path) -> None:
    directory = _unbounded(tmp_path)
    recovered = recover_evidence(directory)
    assert recovered.status == "ok"
    assert [item.event.seq for item in recovered.events] == [0, 1, 2]
    assert all(item.integrity == "chained" for item in recovered.events)
    assert recovered.receipt_status == "not applicable to offline evaluation"
    assert recovered.journal_evicted_frames == 0


def test_recovery_reports_tombstone_and_journal_only(tmp_path: Path) -> None:
    trace, labels = _inputs(tmp_path)
    reference = run_evaluation(
        trace, labels, tmp_path / "reference", strategy=UnboundedStrategy(),
        journal_bytes=2048, budget_bytes=None, unbounded_bytes_retained=None,
        git_commit="a" * 40, git_dirty=False, tool_versions=_versions(), set_role="tuning",
    )
    assert reference.bytes_retained is not None
    output = tmp_path / "budgeted"
    run_evaluation(
        trace, labels, output, strategy=PolicyStrategy("priority", segment_events=1),
        journal_bytes=2048, budget_bytes=4096,
        unbounded_bytes_retained=reference.bytes_retained,
        git_commit="a" * 40, git_dirty=False, tool_versions=_versions(), set_role="tuning",
    )
    recovered = recover_evidence(output)
    assert recovered.status == "incomplete"
    assert recovered.tombstones >= 1
    assert any(item.integrity == "journal_only" for item in recovered.events)
    assert any(issue.kind == "tombstone" for issue in recovered.issues)


def test_recovery_does_not_accept_corrupt_journal_as_complete(tmp_path: Path) -> None:
    directory = _unbounded(tmp_path)
    journal_path = directory / "journal.bin"
    with journal_path.open("r+b") as stream:
        stream.seek(72)
        original = stream.read(1)
        stream.seek(72)
        stream.write(bytes([original[0] ^ 1]))
    recovered = recover_evidence(directory)
    assert recovered.status == "incomplete"
    assert recovered.journal_status == "incomplete"
    assert any(issue.kind == "incomplete_write" and issue.seq_range is None
               for issue in recovered.issues)
    assert all(item.integrity == "chained" for item in recovered.events)


def test_torn_journal_gap_records_known_neighbors_and_auto_limitation(tmp_path: Path) -> None:
    directory = _unbounded(tmp_path)
    journal_path = directory / "journal.bin"
    first = recover_journal(journal_path).events[0]
    second_payload_offset = 64 + 8 + len(first.to_json()) + 8
    with journal_path.open("r+b") as stream:
        stream.seek(second_payload_offset)
        original = stream.read(1)
        stream.seek(second_payload_offset)
        stream.write(bytes([original[0] ^ 1]))
    recovered = recover_evidence(directory)
    gap = next(item for item in recovered.issues if item.reason ==
               "crc_failure_unreadable_payload")
    assert gap.seq_range is None and gap.ts_range_ns is None
    assert gap.last_valid_seq == 0
    assert gap.next_valid_seq == 1
    reconstruction = build_reconstruction(recovered)
    assert any("Unknown sequence and timestamp bounds" in item
               for item in reconstruction.limitations)
    assert Reconstruction.from_dict(json.loads(reconstruction.to_json())) == reconstruction
