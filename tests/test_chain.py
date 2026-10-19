"""Chain continuity after eviction and incomplete-state classification."""

import json
import re
from pathlib import Path
from uuid import UUID, uuid5

from vmbox.integrity.chain import verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.schema import Event, SessionManifest
from vmbox.store.segment import SelectionStats, seal_segment
from vmbox.store.tombstone import evict_segment


def examples():
    schema = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    return [json.loads(block) for block in re.findall(r"```json\s*(.*?)```", schema, re.DOTALL)]


def event(seq):
    data = examples()[0]
    data["seq"] = seq
    data["event_id"] = str(uuid5(UUID(data["session_id"]), str(seq)))
    return Event.from_dict(data)


def manifest():
    data = examples()[1]
    data["session_id"] = event(0).session_id
    return SessionManifest.from_dict(data)


def test_chain_verifies_across_tombstone(tmp_path: Path):
    m = manifest()
    genesis = "sha256:" + manifest_genesis(m).hex()
    first = tmp_path / "seg_00000000.vseg"
    footer = seal_segment(first, index=0, events=[event(0)], prev_hash=genesis,
                          strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    second = tmp_path / "seg_00000001.vseg"
    seal_segment(second, index=1, events=[event(1)], prev_hash=footer.segment_hash,
                 strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    evict_segment(first, tmp_path / "seg_00000000.tomb", genesis, 10)
    result = verify_chain(tmp_path, m)
    assert result.status == "ok"
    assert [entry.kind for entry in result.entries] == ["tombstone", "segment"]


def test_chain_flags_gap_conflict_and_unsealed_temp(tmp_path: Path):
    m = manifest()
    genesis = "sha256:" + manifest_genesis(m).hex()
    second = tmp_path / "seg_00000001.vseg"
    seal_segment(second, index=1, events=[event(1)], prev_hash=genesis,
                 strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    assert verify_chain(tmp_path, m).status == "incomplete"
    first = tmp_path / "seg_00000000.vseg"
    seal_segment(first, index=0, events=[event(0)], prev_hash=genesis,
                 strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    assert verify_chain(tmp_path, m).status == "tampered"
    first.with_name("seg_00000000.tomb").write_bytes(b"partial")
    assert verify_chain(tmp_path, m).status == "incomplete"
    first.with_name("seg_00000000.tomb").unlink()
    first.with_name("seg_00000002.vseg.tmp").write_bytes(b"partial")
    assert verify_chain(tmp_path, m).status == "incomplete"
