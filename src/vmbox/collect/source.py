"""Small capture interface for the M1 measurement spike."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class RawEvent:
    source: str
    event_type: str
    payload: dict[str, Any]


EventSink = Callable[[RawEvent], None]


class Source(Protocol):
    name: str

    def events(self) -> Iterator[RawEvent]: ...

    def start(self, sink: EventSink) -> None: ...

    def stop(self) -> None: ...

    def loss_counters(self) -> dict[str, int | None]: ...
