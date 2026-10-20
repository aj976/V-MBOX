"""Synthetic label-matching cases; no VM observation is implied."""

import json
import re
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid5

import pytest

from vmbox.eval.matching import (
    apply_review,
    match_labels,
    read_match_review,
    resolve_match_review,
    write_match_review,
)
from vmbox.eval.labels import freeze_labels
from vmbox.schema import Event, GroundTruthLabel, ReviewResolution


def _example(model_index: int):
    schema = (Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md").read_text(
        encoding="utf-8")
    return json.loads(re.findall(r"```json\s*(.*?)```", schema, re.DOTALL)[model_index])


def _labels():
    data = _example(6)
    data["anchor"] = {"nonce": "n123", "event_type": "PROC_START",
                      "image_regex": r".*vmbox_anchor_n123\.exe$"}
    data["steps"] = [
        {"step_id": "s1", "description": "target process", "relevance": "attack",
         "match": {"event_type": "PROC_START", "image_regex": r".*target\.exe$",
                   "ts_window_ns": [-10, 10], "pid_lineage": None}},
        {"step_id": "s2", "description": "target connection", "relevance": "attack",
         "match": {"event_type": "NET_CONNECT", "image_regex": r".*target\.exe$",
                   "ts_window_ns": [-10, 10],
                   "pid_lineage": {"step_id": "s1", "relation": "same_pid"}}},
    ]
    return GroundTruthLabel.from_dict(data)


def _event(seq: int, ts: int, image: str, *, event_type: str = "PROC_START",
           pid: int = 10, ppid: int = 1):
    data = _example(0)
    data.update(seq=seq, ts_ns=ts, event_id=str(uuid5(UUID(data["session_id"]), str(seq))),
                event_type=event_type, category="network" if event_type == "NET_CONNECT"
                else "process", pid=pid, ppid=ppid)
    data["process"]["image"] = image
    return Event.from_dict(data)


def test_anchor_missing_or_duplicated_is_hard_error():
    labels = _labels()
    target = _event(1, 100, "C:/target.exe")
    with pytest.raises(ValueError, match="found 0"):
        match_labels(labels, [target])
    marker = _event(0, 100, "C:/vmbox_anchor_n123.exe")
    with pytest.raises(ValueError, match="found 2"):
        match_labels(labels, [marker, replace(marker)])


def test_inclusive_edges_and_time_shift_invariance():
    labels = _labels()
    marker = _event(0, 100, "C:/vmbox_anchor_n123.exe")
    start = _event(1, 90, "C:/target.exe", pid=20)
    end = _event(2, 110, "C:/target.exe", event_type="NET_CONNECT", pid=20)
    events = [marker, start, end]
    result = match_labels(labels, events)
    assert result.matched == {"s1": start.event_id, "s2": end.event_id}
    shifted = [replace(event, ts_ns=event.ts_ns + 1000000000) for event in events]
    assert match_labels(labels, shifted).matched == result.matched
    assert "s1" in match_labels(labels, [marker, replace(start, ts_ns=89), end]).collection_misses
    assert "s2" in match_labels(labels, [marker, start,
        replace(end, ts_ns=111)]).collection_misses
    assert "s1" in match_labels(labels, [marker, replace(start, ts_ns=111), end]).collection_misses
    assert "s2" in match_labels(labels, [marker, start,
        replace(end, ts_ns=89)]).collection_misses


def test_identity_and_lineage_must_match_not_just_time():
    labels = _labels()
    marker = _event(0, 100, "C:/vmbox_anchor_n123.exe")
    wrong_image = _event(1, 100, "C:/other.exe")
    wrong_type = _event(2, 100, "C:/target.exe", event_type="NET_CONNECT")
    result = match_labels(labels, [marker, wrong_image, wrong_type])
    assert result.collection_misses == {"s1"}
    assert result.blocked == {"s2"}
    start = _event(3, 100, "C:/target.exe", pid=20)
    wrong_pid = _event(4, 100, "C:/target.exe", event_type="NET_CONNECT", pid=21)
    result = match_labels(labels, [marker, start, wrong_pid])
    assert result.collection_misses == {"s2"}


def test_ambiguity_goes_to_review_and_review_is_frozen(tmp_path: Path):
    labels = _labels()
    marker = _event(0, 100, "C:/vmbox_anchor_n123.exe")
    first = _event(1, 99, "C:/target.exe", pid=20)
    second = _event(2, 101, "C:/target.exe", pid=21)
    result = match_labels(labels, [marker, first, second])
    assert result.matched == {}
    assert result.blocked == {"s2"}
    assert result.collection_misses == set()
    assert result.review.ambiguous[0].candidate_event_ids == [first.event_id, second.event_id]
    path = tmp_path / "match_review.json"
    write_match_review(path, result.review)
    assert read_match_review(path) == result.review
    with pytest.raises(ValueError, match="unresolved"):
        apply_review(labels, result.review)
    resolution = ReviewResolution("s1", first.event_id, "reviewer-a", 123)
    reviewed = resolve_match_review(path, "s1", first.event_id, "reviewer-a",
                                    clock=lambda: 123)
    assert read_match_review(path) == reviewed
    with pytest.raises(ValueError, match="already reviewed"):
        resolve_match_review(path, "s1", second.event_id, "reviewer-b", clock=lambda: 124)
    frozen_labels = apply_review(labels, reviewed)
    assert frozen_labels.review_resolutions == [resolution]
    matched = match_labels(frozen_labels, [marker, first, second])
    assert matched.matched["s1"] == first.event_id
    assert frozen_labels.to_json() != labels.to_json()
    first_hash = freeze_labels(tmp_path / "labels-first.json", frozen_labels)
    other_reviewer = replace(frozen_labels, review_resolutions=[
        replace(resolution, reviewer="reviewer-b")])
    second_hash = freeze_labels(tmp_path / "labels-second.json", other_reviewer)
    assert first_hash != second_hash
