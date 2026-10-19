import pytest
from hypothesis import given
from hypothesis import strategies as st

from vmbox.normalize.sequence import SequenceCounter


@given(first=st.integers(min_value=0, max_value=2**63 - 100),
       count=st.integers(min_value=1, max_value=100))
def test_sequence_is_monotonic_and_has_no_duplicates(first: int, count: int) -> None:
    counter = SequenceCounter(first)
    assert [counter.assign() for _ in range(count)] == list(range(first, first + count))


def test_sequence_rejects_negative_start() -> None:
    with pytest.raises(ValueError):
        SequenceCounter(-1)
