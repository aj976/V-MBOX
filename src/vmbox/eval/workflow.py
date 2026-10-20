"""Replay a verified trace for label review and freeze, without strategy tuning."""

from pathlib import Path

from vmbox.collect.trace import read_trace
from vmbox.eval.labels import freeze_labels, read_labels
from vmbox.eval.matching import (
    MatchResult,
    apply_review,
    match_labels,
    read_match_review,
    write_match_review,
)
from vmbox.normalize.normalizer import Normalizer
from vmbox.schema import Event


def normalized_trace(path: Path) -> list[Event]:
    header, records = read_trace(path)
    normalizer = Normalizer(header)
    return [normalizer.normalize(record) for record in records]


def prepare_match_review(trace_path: Path, draft_labels_path: Path,
                         review_path: Path) -> MatchResult:
    labels = read_labels(draft_labels_path)
    result = match_labels(labels, normalized_trace(trace_path))
    write_match_review(review_path, result.review)
    return result


def freeze_reviewed_labels(trace_path: Path, draft_labels_path: Path,
                           review_path: Path, frozen_labels_path: Path) -> tuple[str, MatchResult]:
    draft = read_labels(draft_labels_path)
    reviewed = apply_review(draft, read_match_review(review_path))
    result = match_labels(reviewed, normalized_trace(trace_path))
    if result.blocked or any(item.resolution is None for item in result.review.ambiguous):
        raise ValueError("label matching remains unresolved")
    digest = freeze_labels(frozen_labels_path, reviewed)
    return digest, result
