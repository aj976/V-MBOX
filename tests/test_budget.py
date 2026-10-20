"""M3 budget never exceeds cap, including temporary tombstone publication."""

import json
import re
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid5

from vmbox.integrity.chain import verify_chain
from vmbox.schema import Event, SessionManifest
from vmbox.store.budget import BudgetedSegmentStore, BudgetExhausted, retained_bytes
from vmbox.store.journal import create_journal
from vmbox.store.segment import SelectionStats


def examples():
    schema = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    return [json.loads(block) for block in re.findall(r"```json\s*(.*?)```", schema, re.DOTALL)]


def event(seq):
    data = examples()[0]
    data["seq"] = seq
    data["event_id"] = str(uuid5(UUID(data["session_id"]), str(seq)))
    return Event.from_dict(data)


def test_budget_never_overruns_and_chain_survives_eviction(tmp_path: Path):
    data = examples()[1]
    data.update(session_id=event(0).session_id, journal_bytes=1024, budget_bytes=4000)
    manifest = SessionManifest.from_dict(data)
    create_journal(tmp_path / "journal.bin", manifest.journal_bytes)
    store = BudgetedSegmentStore(tmp_path, manifest)
    sealed = 0
    for seq in range(30):
        try:
            store.seal([event(seq)], "fixed", SelectionStats(1, 1, 0, {}, 0),
                       evicted_ts_ns=seq)
        except BudgetExhausted:
            break
        sealed += 1
        assert retained_bytes(tmp_path) <= manifest.budget_bytes
        assert verify_chain(tmp_path, manifest).status == "ok"
    assert sealed > 1
    assert any(tmp_path.glob("*.tomb"))
    assert retained_bytes(tmp_path) <= manifest.budget_bytes


def test_retained_bytes_same_for_live_and_offline_and_excludes_receipts(tmp_path: Path):
    live = SessionManifest.from_dict(examples()[1])
    offline = replace(live, mode="offline_eval", anchor=None)
    values = []
    for mode, manifest in [("live", live), ("offline", offline)]:
        root = tmp_path / mode
        root.mkdir()
        create_journal(root / "journal.bin", manifest.journal_bytes)
        (root / "seg_00000000.vseg").write_bytes(b"same segment bytes")
        (root / "seg_00000001.tomb").write_bytes(b"same tombstone bytes")
        (root / "receipts").mkdir()
        (root / "receipts" / "receipt.json").write_bytes(b"excluded")
        values.append(retained_bytes(root))
    assert values[0] == values[1] == live.journal_bytes + 18 + 20
