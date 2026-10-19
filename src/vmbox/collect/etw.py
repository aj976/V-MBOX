"""Throwaway pywintrace ETW probe. Unverified until run on Windows VM."""

import queue
from collections.abc import Iterator
from typing import Any

from vmbox.collect.source import EventSink, RawEvent


class EtwSource:
    name = "etw"

    def __init__(self, process_guid: str, network_guid: str) -> None:
        self.process_guid = process_guid
        self.network_guid = network_guid
        self._job: Any = None
        self._loss: dict[str, int | None] = {
            "etw_events_lost": None, "etw_log_buffers_lost": None,
            "etw_realtime_buffers_lost": None,
        }

    def start(self, sink: EventSink) -> None:
        import etw  # type: ignore[import-not-found]  # VM dependency

        providers = [
            etw.ProviderInfo("Microsoft-Windows-Kernel-Process", etw.GUID(self.process_guid)),
            etw.ProviderInfo("Microsoft-Windows-Kernel-Network", etw.GUID(self.network_guid)),
        ]

        def callback(item: tuple[int, dict[str, Any]]) -> None:
            event_id, payload = item
            provider = str(payload.get("EventHeader", {}).get("ProviderId", "unknown"))
            task = str(payload.get("Task Name", f"event_{event_id}"))
            provider = provider.strip("{}").lower()
            if provider == self.process_guid.strip("{}").lower():
                source = "etw_kernel_process"
            elif provider == self.network_guid.strip("{}").lower():
                source = "etw_kernel_network"
            else:
                source = "etw_unknown"
            sink(RawEvent(source, task, payload))

        self._job = etw.ETW(providers=providers, event_callback=callback,
                            session_name="vmbox-m1-spike")
        self._job.start()

    def events(self) -> Iterator[RawEvent]:
        """DESIGN Source iterator; caller closes it to stop the probe."""
        pending: queue.Queue[RawEvent] = queue.Queue()
        self.start(pending.put)
        try:
            while True:
                yield pending.get()
        finally:
            self.stop()

    def stop(self) -> None:
        if self._job is None:
            return
        self._job.stop()
        # pywintrace exposes ETW session properties. This counter path is
        # unverified until run on Windows VM; None remains "not measured".
        try:
            props = self._job.properties.get().contents
            self._loss = {
                "etw_events_lost": int(props.EventsLost),
                "etw_log_buffers_lost": int(props.LogBuffersLost),
                "etw_realtime_buffers_lost": int(props.RealTimeBuffersLost),
            }
        except (AttributeError, TypeError, ValueError):
            pass

    def loss_counters(self) -> dict[str, int | None]:
        return self._loss.copy()
