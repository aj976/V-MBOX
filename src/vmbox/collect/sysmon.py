"""VM-derived Sysmon callback; merged revision unverified until run on Windows VM."""

import threading
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from queue import Empty, Queue
from typing import Any

from vmbox.collect.source import EventSink, RawEvent

SYSMON_TYPES = {
    1: "PROC_START",
    3: "NET_CONNECT",
    5: "PROC_EXIT",
    7: "MEM_IMAGE_LOAD",
    8: "MEM_REMOTE_THREAD",
    10: "MEM_PROCESS_ACCESS",
}

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

QUERY = (
    "*[System[(EventID=1 or EventID=3 or EventID=5 or "
    "EventID=7 or EventID=8 or EventID=10)]]"
)


def parse_sysmon_xml(xml: str) -> RawEvent:
    """Parse a Sysmon event; the trace writer hashes command lines before persistence."""
    root = ET.fromstring(xml)
    namespace = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    id_node = root.find("./e:System/e:EventID", namespace)
    if id_node is None or id_node.text is None:
        raise ValueError("Sysmon event has no EventID")

    event_id = int(id_node.text)
    if event_id not in SYSMON_TYPES:
        raise ValueError(f"unexpected Sysmon event ID: {event_id}")

    data: dict[str, Any] = {"event_id": event_id}

    record_id = root.find("./e:System/e:EventRecordID", namespace)
    if record_id is not None and record_id.text:
        data["record_id"] = int(record_id.text)

    for item in root.findall("./e:EventData/e:Data", namespace):
        name = item.get("Name")
        if name:
            # Passed transiently to the trace writer; it persists only a hash
            # unless local-only raw-command-line capture is explicitly enabled.
            data[name] = item.text

    return RawEvent("sysmon", SYSMON_TYPES[event_id], data)


class SysmonSource:
    name = "sysmon"

    def __init__(self) -> None:
        self._subscription: Any = None
        self._error: Exception | None = None
        self._lock = threading.Lock()
        self._sink: EventSink | None = None
        self._pending: Queue[RawEvent] | None = None

    def start(self, sink: EventSink) -> None:
        import win32evtlog  # type: ignore[import-untyped]

        if self._subscription is not None:
            raise RuntimeError("Sysmon source is already running")

        self._error = None
        self._sink = sink

        def callback(action: int, context: Any, event: Any) -> None:
            del context

            if action == win32evtlog.EvtSubscribeActionError:
                with self._lock:
                    self._error = RuntimeError(
                        f"Windows Event Log subscription callback error: {event}"
                    )
                return

            if action != win32evtlog.EvtSubscribeActionDeliver:
                return

            try:
                xml = win32evtlog.EvtRender(
                    event,
                    win32evtlog.EvtRenderEventXml,
                )
                raw_event = parse_sysmon_xml(xml)

                target = self._sink
                if target is not None:
                    target(raw_event)

            except Exception as exc:
                with self._lock:
                    if self._error is None:
                        self._error = exc

        self._subscription = win32evtlog.EvtSubscribe(
            CHANNEL,
            win32evtlog.EvtSubscribeToFutureEvents,
            Callback=callback,
            Query=QUERY,
        )

    def events(self) -> Iterator[RawEvent]:
        """Yield events until the iterator is closed."""
        pending: Queue[RawEvent] = Queue()
        self._pending = pending
        self.start(pending.put)

        try:
            while True:
                try:
                    yield pending.get(timeout=0.5)
                except Empty:
                    with self._lock:
                        error = self._error
                    if error is not None:
                        raise RuntimeError(
                            "Sysmon subscription failed"
                        ) from error
        finally:
            self.stop()
            self._pending = None

    def stop(self) -> None:
        subscription = self._subscription
        self._subscription = None
        self._sink = None

        if subscription is not None:
            subscription.Close()

        with self._lock:
            error = self._error
            self._error = None

        if error is not None:
            raise RuntimeError("Sysmon subscription failed") from error

    def loss_counters(self) -> dict[str, int | None]:
        # EvtSubscribe does not expose a producer-loss count here.
        return {"sysmon_upstream_lost": None}
