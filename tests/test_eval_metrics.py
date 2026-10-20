"""Hand-computed synthetic metric cases, not lab measurements."""

import pytest

from vmbox.eval.metrics import (
    LatencyPercentiles,
    RelationScores,
    budget_fraction_of_full,
    crash_recovery_rate,
    event_loss_rate,
    latency_percentiles_ms,
    mean_with_bootstrap_ci95,
    order_agreement,
    relation_scores,
    storage_efficiency,
)


def test_order_and_relations():
    assert order_agreement(["a", "b", "c"], ["a", "b", "c"]) == 1.0
    assert order_agreement(["a", "b", "c"], ["c", "b", "a"]) == -1.0
    assert order_agreement(["a", "b", "c"], ["b", "a", "c"]) == pytest.approx(1 / 3)
    assert order_agreement(["a"], ["a"]) is None
    with pytest.raises(ValueError):
        order_agreement(["a", "b"], ["a", "c"])
    assert relation_scores({("parent", "a", "b"), ("parent", "b", "c")},
                           {("parent", "a", "b"), ("parent", "a", "c")}) == RelationScores(
        0.5, 0.5)
    assert relation_scores(set(), set()) == RelationScores(None, None)


def test_storage_loss_latency_and_recovery():
    assert budget_fraction_of_full(256, 1024) == 0.25
    assert budget_fraction_of_full(2048, 1024) == 2.0
    with pytest.raises(ValueError):
        budget_fraction_of_full(10, 0)
    assert storage_efficiency(2, 1_048_576) == 2.0
    assert storage_efficiency(0, 0) is None
    assert event_loss_rate({"a", "b", "c", "d"}, {"a"}, {"b"}) == 0.5
    assert event_loss_rate(set(), set(), set()) is None
    assert latency_percentiles_ms([(0, 1_000_000), (0, 2_000_000),
                                   (0, 3_000_000)]) == LatencyPercentiles(2.0, 3.0)
    assert latency_percentiles_ms([]) == LatencyPercentiles(None, None)
    assert crash_recovery_rate({"a", "b"}, {"a"}) == 0.5
    assert crash_recovery_rate(set(), set()) is None
    with pytest.raises(ValueError):
        event_loss_rate({"a"}, {"a"}, {"a"})
    with pytest.raises(ValueError):
        latency_percentiles_ms([(2, 1)])


def test_bootstrap_is_seeded_and_null_without_replicates():
    assert mean_with_bootstrap_ci95([1.0], seed=1) is None
    result = mean_with_bootstrap_ci95([1.0, 3.0, 5.0], seed=4)
    assert result == mean_with_bootstrap_ci95([1.0, 3.0, 5.0], seed=4)
    assert result[0] == 3.0
    assert result[1] <= 3.0 <= result[2]
