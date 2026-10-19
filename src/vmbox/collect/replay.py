"""Replay a verified raw trace in original arrival order."""

from collections.abc import Iterator
from uuid import uuid4

from vmbox.collect.source import EventSink, RawEvent
from vmbox.collect.trace import TraceHeader, TraceRecord


class ReplaySource:
    name = "replay"

    def __init__(self, header: TraceHeader, records: list[TraceRecord]) -> None:
        self.header = header
        self._records = records
        self.run_id = str(uuid4())

    def events(self) -> Iterator[RawEvent]:
        for record in self._records:
            yield RawEvent(record.source, record.event_type, record.payload.copy())

    def records(self) -> Iterator[TraceRecord]:
        yield from self._records

    def start(self, sink: EventSink) -> None:
        for event in self.events():
            sink(event)

    def stop(self) -> None:
        pass

    def loss_counters(self) -> dict[str, int | None]:
        return {"replay_upstream_lost": None}
