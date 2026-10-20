"""M7 process links remain conservative under PID reuse."""

from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid5

from test_eval_harness import _inputs

from vmbox.collect.trace import read_trace
from vmbox.normalize.normalizer import Normalizer
from vmbox.reconstruct.relations import build_relations, build_timeline
from vmbox.recover.evidence import RecoveredEvent
from vmbox.schema import Event, ProcessInfo


def _base(tmp_path: Path) -> Event:
    trace, _ = _inputs(tmp_path)
    header, records = read_trace(trace)
    return Normalizer(header).normalize(records[0])


def _event(base: Event, seq: int, kind: str, category: str, pid: int, ppid: int,
           image: str) -> Event:
    return replace(base, seq=seq, event_id=str(uuid5(UUID(base.session_id), str(seq))),
                   ts_ns=100 + seq, event_type=kind, category=category,
                   pid=pid, ppid=ppid, process=ProcessInfo(image, "sha256:test", None))


def test_reused_pid_links_only_to_active_start(tmp_path: Path) -> None:
    base = _base(tmp_path)
    parent = _event(base, 0, "PROC_START", "process", 10, 1, "parent.exe")
    exit_parent = _event(base, 1, "PROC_EXIT", "process", 10, 1, "parent.exe")
    reused = _event(base, 2, "PROC_START", "process", 10, 1, "parent.exe")
    child = _event(base, 3, "PROC_START", "process", 11, 10, "child.exe")
    connection = _event(base, 4, "NET_CONNECT", "network", 11, 10, "child.exe")
    events = tuple(RecoveredEvent(item, "chained") for item in (
        parent, exit_parent, reused, child, connection
    ))
    relations = build_relations(events)
    assert [(item.type, item.from_, item.to) for item in relations] == [
        ("parent_of", reused.event_id, child.event_id),
        ("spawned_then_connected", child.event_id, connection.event_id),
    ]
    assert [entry.ref for entry in build_timeline(events)] == [
        item.event.event_id for item in events
    ]


def test_temporal_link_is_inferred_low_and_image_mismatch_is_not_derived(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    start = _event(base, 0, "PROC_START", "process", 10, 1, "a.exe")
    memory = _event(base, 1, "MEM_PROCESS_ACCESS", "memory", 10, 1, "a.exe")
    network = _event(base, 2, "NET_CONNECT", "network", 10, 1, "different.exe")
    relations = build_relations(tuple(RecoveredEvent(item, "chained") for item in (
        start, memory, network
    )))
    assert len(relations) == 1
    assert relations[0].type == "temporal_proximity"
    assert relations[0].provenance == "inferred"
    assert relations[0].confidence == "low"


def test_temporal_link_does_not_cross_pid_reuse(tmp_path: Path) -> None:
    base = _base(tmp_path)
    events = (
        _event(base, 0, "PROC_START", "process", 10, 1, "a.exe"),
        _event(base, 1, "MEM_PROCESS_ACCESS", "memory", 10, 1, "a.exe"),
        _event(base, 2, "PROC_EXIT", "process", 10, 1, "a.exe"),
        _event(base, 3, "PROC_START", "process", 10, 1, "b.exe"),
        _event(base, 4, "NET_CONNECT", "network", 10, 1, "b.exe"),
    )
    relations = build_relations(tuple(RecoveredEvent(item, "chained") for item in events))
    assert all(item.type != "temporal_proximity" for item in relations)
