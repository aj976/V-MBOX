"""Conservative relations from surviving events; no intent or attribution claims."""

from dataclasses import dataclass

from vmbox.recover.evidence import RecoveredEvent
from vmbox.schema import Event, Relation, TimelineEntry

_WINDOW_NS = 5_000_000_000


@dataclass(frozen=True)
class _ProcessInstance:
    start: Event
    image: str


def _target_pid(event: Event) -> int | None:
    value = event.data.get("TargetProcessId", event.data.get("target_pid"))
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def build_timeline(events: tuple[RecoveredEvent, ...]) -> list[TimelineEntry]:
    """Sequence, rather than host wall time, determines the order."""
    if any(left.event.seq >= right.event.seq for left, right in zip(
        events, events[1:], strict=False
    )):
        raise ValueError("recovered events must have strictly increasing sequence")
    return [TimelineEntry(item.event.event_id, item.event.ts_ns, item.integrity)
            for item in events]


def build_relations(events: tuple[RecoveredEvent, ...]) -> list[Relation]:
    """Resolve PID reuse against observed starts and exits; uncertain links are omitted."""
    build_timeline(events)
    active: dict[int, _ProcessInstance] = {}
    recent_memory: dict[int, Event] = {}
    raw_relations: list[tuple[str, str, str, str, str, str]] = []
    for item in events:
        event = item.event
        if event.pid is None:
            continue
        if event.event_type == "PROC_START":
            recent_memory.pop(event.pid, None)
            if event.ppid is not None and event.ppid != event.pid:
                parent = active.get(event.ppid)
                if parent is not None:
                    raw_relations.append(("parent_of", parent.start.event_id, event.event_id,
                                          "active parent start and child PPID", "derived",
                                          "medium"))
            if event.process is not None:
                active[event.pid] = _ProcessInstance(event, event.process.image)
            else:
                active.pop(event.pid, None)
        elif event.event_type == "PROC_EXIT":
            recent_memory.pop(event.pid, None)
            instance = active.get(event.pid)
            if instance is not None and (event.process is None or
                                         instance.image == event.process.image):
                active.pop(event.pid)
        else:
            instance = active.get(event.pid)
            if event.event_type == "NET_CONNECT" and instance is not None \
                    and event.process is not None and event.process.image == instance.image:
                raw_relations.append(("spawned_then_connected", instance.start.event_id,
                                      event.event_id, "active process start, PID and image",
                                      "derived", "medium"))
            if event.event_type == "MEM_REMOTE_THREAD":
                target = _target_pid(event)
                target_instance = active.get(target) if target is not None else None
                if target_instance is not None and target != event.pid:
                    raw_relations.append(("remote_thread_into", event.event_id,
                                          target_instance.start.event_id,
                                          "reported target PID matched active process start",
                                          "derived", "medium"))
            if event.event_type in {"MEM_PROCESS_ACCESS", "MEM_REMOTE_THREAD"}:
                recent_memory[event.pid] = event
            elif event.event_type == "NET_CONNECT":
                prior = recent_memory.get(event.pid)
                if prior is not None and 0 <= event.ts_ns - prior.ts_ns <= _WINDOW_NS:
                    raw_relations.append(("temporal_proximity", prior.event_id,
                                          event.event_id, "same PID within time window",
                                          "inferred", "low"))
    return [Relation.from_dict({"relation_id": f"r{index}", "type": relation_type,
                                "from": source, "to": target, "provenance": provenance,
                                "basis": basis, "confidence": confidence})
            for index, (relation_type, source, target, basis, provenance, confidence)
            in enumerate(raw_relations, start=1)]
