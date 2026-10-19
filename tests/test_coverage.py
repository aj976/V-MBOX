"""Hand-computed synthetic coverage cases, not lab measurements."""

import pytest

from vmbox.eval.coverage import Coverage, coverage


def test_coverage_separates_collection_and_selection():
    assert coverage({"a", "b", "c", "d"}, {"a", "b"}, {"a"}) == Coverage(
        collection_coverage=0.5,
        evidence_coverage=0.5,
        end_to_end_coverage=0.25,
    )


def test_undefined_coverage_is_null():
    assert coverage(set(), set(), set()) == Coverage(None, None, None)
    assert coverage({"a"}, set(), set()) == Coverage(0.0, None, 0.0)


def test_coverage_rejects_impossible_subsets():
    with pytest.raises(ValueError):
        coverage({"a"}, {"b"}, set())
    with pytest.raises(ValueError):
        coverage({"a"}, {"a"}, {"b"})
