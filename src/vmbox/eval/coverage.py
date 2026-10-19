"""Coverage metrics from frozen step IDs and observed/persisted matches."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Coverage:
    collection_coverage: float | None
    evidence_coverage: float | None
    end_to_end_coverage: float | None


def coverage(ground_truth: set[str], observed: set[str], persisted: set[str]) -> Coverage:
    """Return null for undefined denominators; never turn unmeasured into zero."""
    if not observed <= ground_truth:
        raise ValueError("observed matches must be ground-truth steps")
    if not persisted <= observed:
        raise ValueError("persisted matches must have been observed")
    collection = len(observed) / len(ground_truth) if ground_truth else None
    evidence = len(persisted) / len(observed) if observed else None
    end_to_end = len(persisted) / len(ground_truth) if ground_truth else None
    return Coverage(collection, evidence, end_to_end)
