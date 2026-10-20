"""Pure M5 metric calculations; absent observations stay null."""

from dataclasses import dataclass
from statistics import mean


@dataclass(frozen=True)
class RelationScores:
    precision: float | None
    recall: float | None


@dataclass(frozen=True)
class LatencyPercentiles:
    p50: float | None
    p95: float | None


def budget_fraction_of_full(budget_bytes: int, unbounded_bytes_retained: int) -> float:
    """Use measured unbounded retained bytes as the shared denominator."""
    if budget_bytes < 0 or unbounded_bytes_retained <= 0:
        raise ValueError("budget needs a positive measured unbounded size")
    return budget_bytes / unbounded_bytes_retained


def order_agreement(expected_order: list[str], observed_order: list[str]) -> float | None:
    """Kendall-style pair agreement on exactly the same unique event IDs."""
    if len(set(expected_order)) != len(expected_order) or set(expected_order) != set(
        observed_order
    ) or len(set(observed_order)) != len(observed_order):
        raise ValueError("order inputs must contain the same unique events")
    n = len(expected_order)
    if n < 2:
        return None
    positions = {event_id: index for index, event_id in enumerate(observed_order)}
    concordant = 0
    discordant = 0
    for index, first in enumerate(expected_order):
        for second in expected_order[index + 1:]:
            if positions[first] < positions[second]:
                concordant += 1
            else:
                discordant += 1
    return (concordant - discordant) / (concordant + discordant)


def relation_scores(expected: set[tuple[str, str, str]],
                    observed: set[tuple[str, str, str]]) -> RelationScores:
    correct = len(expected & observed)
    precision = correct / len(observed) if observed else None
    recall = correct / len(expected) if expected else None
    return RelationScores(precision, recall)


def storage_efficiency(relevant_persisted: int, retained_bytes: int) -> float | None:
    """Relevant retained events per MiB; zero bytes leaves the ratio undefined."""
    if relevant_persisted < 0 or retained_bytes < 0:
        raise ValueError("negative storage input")
    return relevant_persisted * 1_048_576 / retained_bytes if retained_bytes else None


def event_loss_rate(generated: set[str], persisted: set[str],
                    selected_dropped: set[str]) -> float | None:
    """Unexplained missing generated events divided by generated events."""
    if not persisted <= generated or not selected_dropped <= generated:
        raise ValueError("unknown event ID")
    if persisted & selected_dropped:
        raise ValueError("event cannot be both persisted and selected out")
    if not generated:
        return None
    return len(generated - persisted - selected_dropped) / len(generated)


def latency_percentiles_ms(observed_and_durable_ns: list[tuple[int, int]]) -> LatencyPercentiles:
    """Nearest-rank percentiles of measured durability latency only."""
    if not observed_and_durable_ns:
        return LatencyPercentiles(None, None)
    latencies = []
    for observed, durable in observed_and_durable_ns:
        if observed < 0 or durable < observed:
            raise ValueError("invalid durability timestamp pair")
        latencies.append((durable - observed) / 1_000_000)
    latencies.sort()

    def rank(percent: int) -> float:
        return latencies[(percent * len(latencies) + 99) // 100 - 1]
    return LatencyPercentiles(rank(50), rank(95))


def crash_recovery_rate(committed: set[str], recovered: set[str]) -> float | None:
    if not recovered <= committed:
        raise ValueError("recovered IDs must be committed")
    return len(recovered) / len(committed) if committed else None


def mean_with_bootstrap_ci95(values: list[float], seed: int,
                             replications: int = 1000) -> tuple[float, float, float] | None:
    """Deterministic percentile bootstrap; requires at least two independent runs."""
    import math
    import random

    if seed < 0 or replications < 100 or any(not math.isfinite(value) for value in values):
        raise ValueError("invalid bootstrap inputs")
    if len(values) < 2:
        return None
    rng = random.Random(seed)
    boot = sorted(mean(rng.choices(values, k=len(values))) for _ in range(replications))
    lower = boot[int(0.025 * replications)]
    upper = boot[min(replications - 1, int(0.975 * replications))]
    return mean(values), lower, upper
