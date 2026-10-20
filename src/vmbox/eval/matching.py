"""Match frozen scenario steps to a normalized trace via a unique nonce anchor."""

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from time import time_ns

from vmbox.canonical import canonical_json
from vmbox.schema import (
    AmbiguousMatch,
    Event,
    GroundTruthLabel,
    MatchReview,
    ReviewCandidate,
    ReviewResolution,
)


@dataclass(frozen=True)
class MatchResult:
    anchor_event_id: str
    matched: dict[str, str]
    collection_misses: set[str]
    blocked: set[str]
    review: MatchReview


def _image_matches(event: Event, pattern: str) -> bool:
    return event.process is not None and re.search(pattern, event.process.image) is not None


def match_labels(labels: GroundTruthLabel, events: list[Event]) -> MatchResult:
    """Require one anchor; never infer a missing anchor from wall-clock time."""
    anchor = labels.anchor
    anchors = [event for event in events
               if event.event_type == anchor.event_type
               and event.process is not None
               and anchor.nonce in event.process.image
               and _image_matches(event, anchor.image_regex)]
    if len(anchors) != 1:
        raise ValueError(f"expected exactly one scenario anchor; found {len(anchors)}")
    t0 = anchors[0].ts_ns
    matched: dict[str, str] = {}
    matched_events: dict[str, Event] = {"anchor": anchors[0]}
    misses: set[str] = set()
    blocked: set[str] = set()
    ambiguous: list[AmbiguousMatch] = []
    resolutions = {item.step_id: item for item in labels.review_resolutions}
    used_resolutions: set[str] = set()
    for step in labels.steps:
        rule = step.match
        lineage = rule.pid_lineage
        if lineage is not None and lineage.step_id not in matched_events:
            blocked.add(step.step_id)
            continue
        candidates: list[Event] = []
        for event in events:
            if event.event_type != rule.event_type or not _image_matches(event, rule.image_regex):
                continue
            offset = event.ts_ns - t0
            if not rule.ts_window_ns[0] <= offset <= rule.ts_window_ns[1]:
                continue
            if lineage is not None:
                parent = matched_events[lineage.step_id]
                if parent.pid is None:
                    continue
                candidate_pid = event.pid if lineage.relation == "same_pid" else event.ppid
                if candidate_pid != parent.pid:
                    continue
            candidates.append(event)
        if len(candidates) == 0:
            if step.step_id in resolutions:
                raise ValueError("reviewed step has no current candidates")
            if step.relevance == "attack":
                misses.add(step.step_id)
            continue
        if len(candidates) == 1:
            if step.step_id in resolutions:
                raise ValueError("review resolution exists for unambiguous step")
            chosen = candidates[0]
        else:
            resolution = resolutions.get(step.step_id)
            ids = [item.event_id for item in candidates]
            if resolution is not None and resolution.event_id not in ids:
                raise ValueError("review resolution does not match current candidates")
            summaries = [ReviewCandidate(item.event_id, item.seq, item.ts_ns,
                                         item.event_type, item.process.image,
                                         item.pid, item.ppid) for item in candidates
                         if item.process is not None]
            ambiguous.append(AmbiguousMatch(step.step_id, summaries, resolution))
            if resolution is None:
                continue
            used_resolutions.add(step.step_id)
            chosen = next(item for item in candidates if item.event_id == resolution.event_id)
        matched[step.step_id] = chosen.event_id
        matched_events[step.step_id] = chosen
    if used_resolutions != set(resolutions):
        raise ValueError("unused review resolution")
    return MatchResult(anchors[0].event_id, matched, misses, blocked,
                       MatchReview(labels.run_id, ambiguous))


def write_match_review(path: Path, review: MatchReview) -> None:
    """Write the pre-freeze review workpaper; reviewer fills resolution fields."""
    with path.open("xb") as stream:
        stream.write(canonical_json(review.to_dict()))


def read_match_review(path: Path) -> MatchReview:
    raw = path.read_bytes()
    try:
        review = MatchReview.from_dict(json.loads(raw))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("invalid match review") from exc
    if canonical_json(review.to_dict()) != raw:
        raise ValueError("noncanonical match review")
    return review


def apply_review(labels: GroundTruthLabel, review: MatchReview) -> GroundTruthLabel:
    """Copy resolved reviewer decisions into labels before freeze/hash."""
    if labels.run_id != review.run_id:
        raise ValueError("review run_id mismatch")
    if any(item.resolution is None for item in review.ambiguous):
        raise ValueError("unresolved ambiguous match")
    resolutions: list[ReviewResolution] = [item.resolution for item in review.ambiguous
                                           if item.resolution is not None]
    return replace(labels, review_resolutions=resolutions)


def resolve_match_review(path: Path, step_id: str, event_id: str, reviewer: str,
                         *, clock: Callable[[], int] = time_ns) -> MatchReview:
    """Update the pre-freeze workpaper; frozen labels remain write-once."""
    review = read_match_review(path)
    entries = []
    found = False
    for item in review.ambiguous:
        if item.step_id == step_id:
            if item.resolution is not None:
                raise ValueError("step already reviewed")
            resolution = ReviewResolution(step_id, event_id, reviewer, clock())
            item = replace(item, resolution=resolution)
            found = True
        entries.append(item)
    if not found:
        raise ValueError("step is not in match review")
    updated = replace(review, ambiguous=entries)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(canonical_json(updated.to_dict()))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return updated
