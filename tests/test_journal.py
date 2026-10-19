"""M3 journal unit and property tests; VM kill/power-off remains unverified."""

import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid5

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vmbox.schema import Event
from vmbox.store.journal import append_journal, create_journal, recover_journal


def event(seq: int) -> Event:
    schema = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    example = json.loads(re.findall(r"```json\s*(.*?)```", schema, re.DOTALL)[0])
    example["seq"] = seq
    example["event_id"] = str(uuid5(UUID(example["session_id"]), str(seq)))
    return Event.from_dict(example)


@given(st.integers(min_value=0, max_value=40))
@settings(deadline=None)
def test_journal_ring_retains_ordered_suffix_and_counts_evictions(count: int):
    with TemporaryDirectory() as directory:
        path = Path(directory) / "journal.bin"
        create_journal(path, 2048)
        assert path.stat().st_size == 2048
        expected = [event(seq) for seq in range(count)]
        for item in expected:
            append_journal(path, item)
        recovered = recover_journal(path)
        assert recovered.incomplete_reason is None
        assert recovered.events == expected[recovered.evicted_frames:]
        assert recovered.evicted_frames + len(recovered.events) == count


def test_journal_detects_torn_frame_and_does_not_append(tmp_path: Path):
    path = tmp_path / "journal.bin"
    create_journal(path, 2048)
    append_journal(path, event(0))
    contents = bytearray(path.read_bytes())
    contents[64 + 8 + 10] ^= 1
    path.write_bytes(contents)
    recovered = recover_journal(path)
    assert recovered.incomplete_reason is not None
    assert recovered.events == []
    with pytest.raises(ValueError, match="incomplete"):
        append_journal(path, event(1))


def test_journal_write_once_and_bad_cursor(tmp_path: Path):
    path = tmp_path / "journal.bin"
    create_journal(path, 2048)
    with pytest.raises(FileExistsError):
        create_journal(path, 2048)
    damaged = bytearray(path.read_bytes())
    damaged[28] ^= 1
    path.write_bytes(damaged)
    assert recover_journal(path).incomplete_reason is not None


def test_journal_rejects_out_of_order_append(tmp_path: Path):
    path = tmp_path / "journal.bin"
    create_journal(path, 2048)
    append_journal(path, event(3))
    with pytest.raises(ValueError, match="ascending"):
        append_journal(path, event(2))


def test_journal_rejects_frame_larger_than_ring(tmp_path: Path):
    path = tmp_path / "journal.bin"
    create_journal(path, 128)
    with pytest.raises(ValueError, match="exceeds"):
        append_journal(path, event(0))


@pytest.mark.parametrize("tail", [5, 10])
def test_journal_wrap_padding_both_shapes(tmp_path: Path, tail: int):
    frame_size = 8 + len(event(0).to_json())
    path = tmp_path / "journal.bin"
    create_journal(path, 64 + 3 * frame_size + tail)
    for seq in range(4):
        append_journal(path, event(seq))
    recovered = recover_journal(path)
    assert recovered.incomplete_reason is None
    assert recovered.events == [event(2), event(3)]
    assert recovered.evicted_frames == 2
