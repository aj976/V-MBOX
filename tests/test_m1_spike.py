"""Synthetic shape tests. Real sanitized Sysmon fixtures require the Windows VM run."""

import sys
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest

from vmbox.collect.etw import EtwSource
from vmbox.collect.sysmon import SYSMON_TYPES, SysmonSource, parse_sysmon_xml


def test_sysmon_config_enables_requested_ids():
    root = ET.parse("docs/sysmon.xml").getroot()
    tags = {child.tag for child in root.find("EventFiltering")}
    assert tags == {
        "ProcessCreate", "NetworkConnect", "ProcessTerminate", "ImageLoad",
        "CreateRemoteThread", "ProcessAccess",
    }
    assert all(child.get("onmatch") == "exclude" for child in root.find("EventFiltering"))
    assert set(SYSMON_TYPES) == {1, 3, 5, 7, 8, 10}


def test_sysmon_xml_parses_metadata_without_command_line():
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           "<System><EventID>1</EventID><EventRecordID>123</EventRecordID></System>"
           "<EventData><Data Name='Image'>C:\\test.exe</Data>"
           "<Data Name='CommandLine'>secret</Data></EventData></Event>")
    event = parse_sysmon_xml(xml)
    assert event.event_type == "PROC_START"
    assert event.payload == {"event_id": 1, "record_id": 123, "Image": "C:\\test.exe"}


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

    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(
        CloseHandle=lambda signal: closed.append(signal)))
    source = SysmonSource()
    source._subscription = Handle()
    source._signal = "signal"
    source.stop()
    assert closed == ["subscription", "signal"]
