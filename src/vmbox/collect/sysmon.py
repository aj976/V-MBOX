"""Sysmon event-log subscription for M1. Unverified until run on Windows VM."""

import threading
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from queue import Queue
from typing import Any

from vmbox.collect.source import EventSink, RawEvent

SYSMON_TYPES = {
    1: "PROC_START", 3: "NET_CONNECT", 5: "PROC_EXIT",
    7: "MEM_IMAGE_LOAD", 8: "MEM_REMOTE_THREAD", 10: "MEM_PROCESS_ACCESS",
}
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
QUERY = "*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=7 or EventID=8 or EventID=10)]]"


def parse_sysmon_xml(xml: str) -> RawEvent:
    root = ET.fromstring(xml)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
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
            # The spike counts metadata only; no command lines are persisted.
            if name == "CommandLine":
                continue
            data[name] = item.text
    return RawEvent("sysmon", SYSMON_TYPES[event_id], data)


class SysmonSource:
    name = "sysmon"

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._error: Exception | None = None
        self._subscription: Any = None
        self._signal: Any = None

    def start(self, sink: EventSink) -> None:
        import win32event  # type: ignore  # VM dependency
        import win32evtlog  # type: ignore  # VM dependency

        self._stop.clear()
        self._signal = win32event.CreateEvent(None, False, False, None)
        self._subscription = win32evtlog.EvtSubscribe(
            CHANNEL, win32evtlog.EvtSubscribeToFutureEvents,
            SignalEvent=self._signal, Query=QUERY,
        )

        def consume() -> None:
            try:
                while not self._stop.is_set():
                    # pywin32's EvtNext accepts Timeout in milliseconds.
                    events = win32evtlog.EvtNext(self._subscription, 64, Timeout=500)
                    for event in events:
                        try:
                            xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                            sink(parse_sysmon_xml(xml))
                        finally:
                            event.Close()
            except Exception as exc:
                self._error = exc

        self._thread = threading.Thread(target=consume, name="vmbox-sysmon-m1", daemon=True)
        self._thread.start()

    def events(self) -> Iterator[RawEvent]:
        """DESIGN Source iterator; caller closes it to stop the subscription."""
        pending: Queue[RawEvent] = Queue()
        self.start(pending.put)
        try:
            while True:
                yield pending.get()
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._subscription is not None:
            self._subscription.Close()
        if self._signal is not None:
            import win32api  # type: ignore  # VM dependency
            win32api.CloseHandle(self._signal)
        if self._error:
            raise RuntimeError("Sysmon subscription failed") from self._error

    def loss_counters(self) -> dict[str, int | None]:
        # EvtSubscribe does not expose a producer-loss count in this spike.
        return {"sysmon_upstream_lost": None}
