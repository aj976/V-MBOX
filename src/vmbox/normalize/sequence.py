"""Per-session sequence assignment, owned by the normalizer layer."""


class SequenceCounter:
    """Assign strictly increasing event sequence numbers before selection."""

    def __init__(self, first_seq: int = 0) -> None:
        if first_seq < 0:
            raise ValueError("first_seq must be nonnegative")
        self._next = first_seq

    def assign(self) -> int:
        seq = self._next
        self._next += 1
        return seq
