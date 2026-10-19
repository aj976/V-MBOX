"""M3 sealed segment and byte-tamper tests."""

import json
import re
from pathlib import Path
from uuid import UUID, uuid5

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.segment import verify_segment
from vmbox.schema import Event, SessionManifest
from vmbox.store.segment import SelectionStats, seal_segment


def examples():
    schema = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    return [json.loads(block) for block in re.findall(r"```json\s*(.*?)```", schema, re.DOTALL)]


def event(seq):
    data = examples()[0]
    data["seq"] = seq
    data["event_id"] = str(uuid5(UUID(data["session_id"]), str(seq)))
    return Event.from_dict(data)


def genesis_tag():
    return "sha256:" + manifest_genesis(SessionManifest.from_dict(examples()[1])).hex()


def test_segment_seal_verify_chain_and_write_once(tmp_path: Path):
    first_path = tmp_path / "seg_00000000.vseg"
    stats = SelectionStats(2, 2, 0, {"NET_CONNECT": 2}, 0)
    footer = seal_segment(first_path, index=0, events=[event(1), event(3)],
                          prev_hash=genesis_tag(), strategy="fixed", selection_stats=stats)
    verified = verify_segment(first_path, genesis_tag())
    assert verified.status == "ok"
    assert [item.seq for item in verified.events] == [1, 3]
    assert verified.footer == footer
    with pytest.raises(FileExistsError):
        seal_segment(first_path, index=0, events=[event(1)], prev_hash=genesis_tag(),
                     strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    second_path = tmp_path / "seg_00000001.vseg"
    seal_segment(second_path, index=1, events=[event(5)], prev_hash=footer.segment_hash,
                 strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    assert verify_segment(second_path, footer.segment_hash).status == "ok"
    assert verify_segment(second_path, genesis_tag()).status == "tampered"


@pytest.mark.parametrize("region", ["header", "body", "footer"])
def test_segment_byte_flip_detected(tmp_path: Path, region: str):
    path = tmp_path / "seg_00000000.vseg"
    seal_segment(path, index=0, events=[event(1)], prev_hash=genesis_tag(),
                 strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    data = bytearray(path.read_bytes())
    header_end = data.index(b"\n")
    offsets = {"header": 10, "body": header_end + 8 + 10, "footer": len(data) - 10}
    data[offsets[region]] ^= 1
    path.write_bytes(data)
    result = verify_segment(path, genesis_tag())
    assert result.status == "tampered"
    assert result.reason is not None


def test_segment_torn_footer_never_complete(tmp_path: Path):
    path = tmp_path / "seg_00000000.vseg"
    seal_segment(path, index=0, events=[event(1)], prev_hash=genesis_tag(),
                 strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    path.write_bytes(path.read_bytes()[:-20])
    assert verify_segment(path, genesis_tag()).status == "incomplete"


def test_failed_rename_leaves_only_unsealed_temp(tmp_path: Path, monkeypatch):
    path = tmp_path / "seg_00000000.vseg"

    def fail_rename(source, destination):
        raise OSError("simulated interruption before rename")

    monkeypatch.setattr("vmbox.store.segment.os.rename", fail_rename)
    with pytest.raises(OSError, match="simulated interruption"):
        seal_segment(path, index=0, events=[event(1)], prev_hash=genesis_tag(),
                     strategy="fixed", selection_stats=SelectionStats(1, 1, 0, {}, 0))
    assert not path.exists()
    assert path.with_name(path.name + ".tmp").exists()
    assert verify_segment(path, genesis_tag()).status == "incomplete"


@given(st.lists(st.integers(min_value=0, max_value=10000),
                min_size=1, max_size=6, unique=True), st.integers(min_value=0))
@settings(deadline=None, max_examples=30)
def test_segment_property_roundtrip_and_random_byte_flip(sequences, flip_index):
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as directory:
        path = Path(directory) / "seg_00000000.vseg"
        events = [event(seq) for seq in sorted(sequences)]
        seal_segment(path, index=0, events=events, prev_hash=genesis_tag(),
                     strategy="fixed", selection_stats=SelectionStats(
                         len(events), len(events), 0, {}, 0))
        assert verify_segment(path, genesis_tag()).events == events
        assert verify_segment(path, genesis_tag()).status == "ok"
        original = bytearray(path.read_bytes())
        original[flip_index % len(original)] ^= 1
        path.write_bytes(original)
        assert verify_segment(path, genesis_tag()).status != "ok"
