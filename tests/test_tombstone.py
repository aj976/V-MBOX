"""M3 tombstone corruption and chain-retention tests."""

import json
import re
from pathlib import Path
from uuid import UUID, uuid5

import pytest

from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.tombstone import verify_tombstone
from vmbox.schema import Event, SessionManifest, Tombstone
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


def test_tombstone_example_and_hash_validator():
    data = examples()[2]
    Tombstone.from_dict(data)
    for field in ("index", "record_count", "evicted_ts_ns", "segment_hash"):
        changed = data.copy()
        changed[field] = 1 if type(data[field]) is int else "sha256:" + "0" * 64
        with pytest.raises(ValueError):
            Tombstone.from_dict(changed)


def test_eviction_preserves_chain_digest_and_rejects_byte_flip(tmp_path: Path):
    genesis = "sha256:" + manifest_genesis(SessionManifest.from_dict(examples()[1])).hex()
    segment = tmp_path / "seg_00000000.vseg"
    tomb_path = tmp_path / "seg_00000000.tomb"
    seal_segment(segment, index=0, events=[event(1)], prev_hash=genesis,
                 strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    tomb = evict_segment(segment, tomb_path, genesis, evicted_ts_ns=10)
    assert not segment.exists()
    result = verify_tombstone(tomb_path, genesis, 0)
    assert result.status == "metadata_valid"
    assert result.tombstone == tomb
    assert result.tombstone.segment_hash == tomb.segment_hash
    with pytest.raises(FileExistsError):
        from vmbox.store.tombstone import write_tombstone
        write_tombstone(tomb_path, tomb)
    damaged = bytearray(tomb_path.read_bytes())
    damaged[20] ^= 1
    tomb_path.write_bytes(damaged)
    assert verify_tombstone(tomb_path, genesis, 0).status == "tampered"
