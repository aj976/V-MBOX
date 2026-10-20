"""Frozen M6 offline selection rules. No labels or storage access."""

from dataclasses import asdict, dataclass
from ipaddress import ip_address

from vmbox.canonical import canonical_json
from vmbox.eval.strategy import SelectionOutcome, StrategyName
from vmbox.schema import Event
from vmbox.store.segment import SelectionStats

# Rule changes require a new experiment version; these values are not learned from labels.
RULES_VERSION = "m6-general-v1"
FIXED_TYPES = frozenset({"PROC_START", "PROC_EXIT", "NET_CONNECT", "MEM_REMOTE_THREAD",
                         "MEM_PROCESS_ACCESS", "CAPTURE_GAP"})
BASE_WEIGHT = {"CAPTURE_GAP": 100, "MEM_REMOTE_THREAD": 80,
               "MEM_PROCESS_ACCESS": 60, "NET_CONNECT": 50, "PROC_START": 40,
               "PROC_EXIT": 20, "MEM_IMAGE_LOAD": 10, "NET_CLOSE": 5,
               "COLLECTOR_START": 5, "COLLECTOR_STOP": 5, "MEM_PROTECT_CHANGE": 10}
WINDOW_NS = 5_000_000_000
_HASH = "sha256:" + "0" * 64


def _stats(source: tuple[Event, ...], selected: tuple[Event, ...],
           promoted: frozenset[str] = frozenset()) -> SelectionStats:
    counts: dict[str, int] = {}
    for event in selected:
        counts[event.event_type] = counts.get(event.event_type, 0) + 1
    return SelectionStats(len(source), len(selected), len(source) - len(selected),
                          counts, sum(event.event_id in promoted for event in selected))


def _segment_size(source: tuple[Event, ...], selected: tuple[Event, ...],
                  strategy: StrategyName, promoted: frozenset[str]) -> int:
    """Exact v1 single-segment length; digest values have fixed encoded width."""
    if not selected:
        return 0
    header = {
        "schema_version": 1, "session_id": selected[0].session_id, "index": 0,
        "seq_start": selected[0].seq, "seq_end": selected[-1].seq,
        "record_count": len(selected),
        "ts_start_ns": min(event.ts_ns for event in selected),
        "ts_end_ns": max(event.ts_ns for event in selected),
        "prev_hash": _HASH, "strategy": strategy,
        "selection_stats": asdict(_stats(source, selected, promoted)),
    }
    footer = {"segment_hash": _HASH, "body_sha256": _HASH}
    return (len(canonical_json(header)) + 1 + len(canonical_json(footer)) + 1
            + sum(4 + len(event.to_json()) for event in selected))


def _is_external(event: Event) -> bool:
    if event.event_type != "NET_CONNECT":
        return False
    destination = event.data.get("DestinationIp", event.data.get("destination_ip"))
    if not isinstance(destination, str):
        return False
    try:
        address = ip_address(destination)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_private or address.is_link_local)


def _base_priority(event: Event) -> int:
    return BASE_WEIGHT.get(event.event_type, 0) + (15 if _is_external(event) else 0)


def _promoted(events: tuple[Event, ...]) -> frozenset[str]:
    """Promote observed PID context after temporal correlations, without intent claims."""
    memory: dict[int, Event] = {}
    flagged: dict[int, int] = {}
    triggers: list[tuple[int, int]] = []
    for event in events:
        if event.pid is None:
            continue
        if event.event_type in {"MEM_PROCESS_ACCESS", "MEM_REMOTE_THREAD"}:
            memory[event.pid] = event
        elif event.event_type == "NET_CONNECT" and event.pid in memory:
            prior = memory[event.pid]
            if 0 <= event.ts_ns - prior.ts_ns <= WINDOW_NS:
                triggers.append((event.pid, event.ts_ns))
                flagged[event.pid] = event.ts_ns
        elif event.event_type == "PROC_START" and event.ppid in flagged:
            when = flagged[event.ppid]
            if 0 <= event.ts_ns - when <= WINDOW_NS:
                triggers.append((event.pid, event.ts_ns))
                flagged[event.pid] = event.ts_ns
    return frozenset(event.event_id for event in events if event.pid is not None
                     and any(event.pid == pid and abs(event.ts_ns - when) <= WINDOW_NS
                             for pid, when in triggers))


@dataclass(frozen=True)
class PolicyStrategy:
    name: StrategyName

    def __post_init__(self) -> None:
        if self.name not in {"fifo_ring", "fixed", "priority", "context_aware"}:
            raise ValueError("unsupported budgeted strategy")

    @property
    def rules_version(self) -> str:
        return RULES_VERSION

    def select(self, events: tuple[Event, ...], sealed_bytes_budget: int | None,
               ) -> SelectionOutcome:
        if sealed_bytes_budget is None or sealed_bytes_budget < 0:
            raise ValueError("budgeted strategy requires a nonnegative allowance")
        promoted = _promoted(events) if self.name == "context_aware" else frozenset()
        eligible = (tuple(event for event in events if event.event_type in FIXED_TYPES)
                    if self.name == "fixed" else events)
        if self.name in {"fifo_ring", "fixed"}:
            ranked = eligible if self.name == "fixed" else tuple(reversed(eligible))
        else:
            ranked = tuple(sorted(eligible, key=lambda event: (
                -(_base_priority(event) + (1000 if event.event_id in promoted else 0)),
                event.seq,
            )))
        # Each prefix adds a positive-size event frame. Binary search bounds
        # serialization work on large traces while preserving deterministic ties.
        low, high = 0, len(ranked)
        while low < high:
            middle = (low + high + 1) // 2
            ids = {event.event_id for event in ranked[:middle]}
            candidate = tuple(item for item in eligible if item.event_id in ids)
            if _segment_size(events, candidate, self.name, promoted) <= sealed_bytes_budget:
                low = middle
            else:
                high = middle - 1
        selected_ids = {event.event_id for event in ranked[:low]}
        selected = tuple(event for event in eligible if event.event_id in selected_ids)
        return SelectionOutcome(selected, _stats(events, selected, promoted))
