"""Strategy-facing M5 interface; selectors never receive labels or match results."""

from dataclasses import dataclass
from typing import Literal, Protocol

from vmbox.schema import Event
from vmbox.store.segment import SelectionStats

StrategyName = Literal["unbounded", "fixed", "priority", "context_aware", "fifo_ring"]


@dataclass(frozen=True)
class SelectionOutcome:
    events: tuple[Event, ...]
    stats: SelectionStats


class EvaluationStrategy(Protocol):
    """A selector sees only the normalized stream and its sealed-byte allowance."""

    @property
    def name(self) -> StrategyName: ...

    @property
    def rules_version(self) -> str: ...

    def select(self, events: tuple[Event, ...], sealed_bytes_budget: int | None,
               ) -> SelectionOutcome: ...


@dataclass(frozen=True)
class UnboundedStrategy:
    name: StrategyName = "unbounded"
    rules_version: str = "unbounded-v1"

    def select(self, events: tuple[Event, ...], sealed_bytes_budget: int | None,
               ) -> SelectionOutcome:
        if sealed_bytes_budget is not None:
            raise ValueError("unbounded strategy has no sealed-byte allowance")
        by_type: dict[str, int] = {}
        for event in events:
            by_type[event.event_type] = by_type.get(event.event_type, 0) + 1
        return SelectionOutcome(events, SelectionStats(
            seen=len(events), kept=len(events), dropped_by_policy=0,
            by_type=by_type, promoted_by_context=0,
        ))
