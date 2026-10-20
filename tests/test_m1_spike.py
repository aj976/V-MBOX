"""Synthetic shape tests. Real sanitized Sysmon fixtures require the Windows VM run."""

import sys
import xml.etree.ElementTree as ET
from hashlib import sha256
from types import SimpleNamespace
from uuid import uuid4

import pytest

from vmbox.collect.etw import EtwSource
from vmbox.collect.sysmon import SYSMON_TYPES, SysmonSource, parse_sysmon_xml
from vmbox.collect.trace import TraceHeader, read_trace, write_trace


def test_sysmon_config_enables_requested_ids():
    root = ET.parse("docs/sysmon.xml").getroot()
    tags = {child.tag for child in root.find("EventFiltering")}
    assert tags == {
        "ProcessCreate", "NetworkConnect", "ProcessTerminate", "ImageLoad",
        "CreateRemoteThread", "ProcessAccess",
    }
    assert all(child.get("onmatch") == "exclude" for child in root.find("EventFiltering"))
    assert set(SYSMON_TYPES) == {1, 3, 5, 7, 8, 10}


def test_sysmon_xml_passes_command_line_to_trace_writer(tmp_path):
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           "<System><EventID>1</EventID><EventRecordID>123</EventRecordID></System>"
           "<EventData><Data Name='Image'>C:\\test.exe</Data>"
           "<Data Name='CommandLine'>secret</Data></EventData></Event>")
    event = parse_sysmon_xml(xml)
    assert event.event_type == "PROC_START"
    assert event.payload == {"event_id": 1, "record_id": 123, "Image": "C:\\test.exe",
                             "CommandLine": "secret"}
    header = TraceHeader(1, str(uuid4()), str(uuid4()), "boot", ["sysmon"], "test",
                         "sha256:" + "0" * 64, "sha256:" + "0" * 64,
                         {"windows_build": "synthetic"}, False)
    path = tmp_path / "trace.jsonl"
    write_trace(path, header, [event], receipt_clock=lambda: 123)
    _, records = read_trace(path)
    assert "CommandLine" not in records[0].payload
    assert records[0].payload["CommandLineHash"] == (
        "sha256:" + sha256(b"secret").hexdigest()
    )


def test_sysmon_xml_rejects_missing_event_id():
    with pytest.raises(ValueError):
        parse_sysmon_xml("<Event />")


def test_etw_adapter_counts_only_known_provider(monkeypatch):
    captured = []

    class FakeETW:
        def __init__(self, **kwargs):
            self.callback = kwargs["event_callback"]
            self.properties = SimpleNamespace(get=lambda: SimpleNamespace(contents=SimpleNamespace(
                EventsLost=2, LogBuffersLost=1, RealTimeBuffersLost=0)))

        def start(self):
            self.callback((1, {"EventHeader": {"ProviderId": "{AAAA}"}, "Task Name": "start"}))
            self.callback((2, {"EventHeader": {"ProviderId": "{BBBB}"}, "Task Name": "connect"}))
            self.callback((3, {"EventHeader": {"ProviderId": "{CCCC}"}}))

        def stop(self):
            pass

    fake = SimpleNamespace(ETW=FakeETW, GUID=lambda value: value,
                           ProviderInfo=lambda name, guid: (name, guid))
    monkeypatch.setitem(sys.modules, "etw", fake)
    source = EtwSource("{AAAA}", "{BBBB}")
    source.start(captured.append)
    source.stop()
    assert [item.source for item in captured] == [
        "etw_kernel_process", "etw_kernel_network", "etw_unknown"]
    assert source.loss_counters() == {
        "etw_events_lost": 2, "etw_log_buffers_lost": 1,
        "etw_realtime_buffers_lost": 0,
    }


def test_sysmon_source_closes_subscription_handle(monkeypatch):
    closed = []

    class Handle:
        def Close(self):
            closed.append("subscription")

    source = SysmonSource()
    source._subscription = Handle()
    source.stop()
    assert closed == ["subscription"]


def test_sysmon_callback_delivers_xml_and_surfaces_errors(monkeypatch):
    callbacks = []
    closed = []

    class Handle:
        def Close(self):
            closed.append(True)

    def subscribe(channel, flags, *, Callback, Query):
        assert channel == "Microsoft-Windows-Sysmon/Operational"
        assert "EventID=10" in Query
        callbacks.append(Callback)
        return Handle()

    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           "<System><EventID>1</EventID></System>"
           "<EventData><Data Name='Image'>C:/example.exe</Data></EventData></Event>")
    fake = SimpleNamespace(
        EvtSubscribeActionError=0, EvtSubscribeActionDeliver=1,
        EvtSubscribeToFutureEvents=2, EvtSubscribe=subscribe,
        EvtRenderEventXml=3, EvtRender=lambda event, flag: xml,
    )
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    captured = []
    source = SysmonSource()
    source.start(captured.append)
    callbacks[0](1, None, object())
    assert [event.event_type for event in captured] == ["PROC_START"]
    callbacks[0](0, None, 5)
    with pytest.raises(RuntimeError, match="subscription failed"):
        source.stop()
    assert closed == [True]
