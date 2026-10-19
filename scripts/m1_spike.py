"""M1 telemetry measurement, unverified until run on Windows VM."""

import argparse
import collections
import queue
import sys
import time

from vmbox.collect.etw import EtwSource
from vmbox.collect.source import RawEvent
from vmbox.collect.sysmon import SysmonSource


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, required=True, help="seconds")
    parser.add_argument("--sources", choices=["etw", "sysmon", "both"], default="both")
    parser.add_argument("--etw-process-guid")
    parser.add_argument("--etw-network-guid")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("M1 spike must run on the Windows lab VM")
    if args.duration <= 0:
        parser.error("duration must be positive")
    if args.sources in ("etw", "both") and not (args.etw_process_guid and args.etw_network_guid):
        parser.error("ETW requires both GUIDs from VM provider discovery; see docs/M1_RUNBOOK.md")
    import psutil

    event_queue: queue.Queue[RawEvent] = queue.Queue(maxsize=10000)
    overflow = 0

    def sink(event: RawEvent) -> None:
        nonlocal overflow
        try:
            event_queue.put_nowait(event)
        except queue.Full:
            overflow += 1

    sources = []
    if args.sources in ("etw", "both"):
        sources.append(EtwSource(args.etw_process_guid, args.etw_network_guid))
    if args.sources in ("sysmon", "both"):
        sources.append(SysmonSource())
    process = psutil.Process()
    cpu_start = process.cpu_times()
    start = time.monotonic()
    counts: collections.Counter[str] = collections.Counter()
    peak_rss = process.memory_info().rss
    started = []
    try:
        for source in sources:
            source.start(sink)
            started.append(source)
        while time.monotonic() - start < args.duration:
            try:
                event = event_queue.get(timeout=0.1)
                counts[f"{event.source}:{event.event_type}"] += 1
            except queue.Empty:
                pass
            peak_rss = max(peak_rss, process.memory_info().rss)
    finally:
        for source in reversed(started):
            source.stop()
    elapsed = time.monotonic() - start
    while not event_queue.empty():
        event = event_queue.get_nowait()
        counts[f"{event.source}:{event.event_type}"] += 1
    cpu_end = process.cpu_times()
    cpu_seconds = (cpu_end.user + cpu_end.system) - (cpu_start.user + cpu_start.system)
    print(f"duration_s: {elapsed:.3f}")
    print(f"events_total: {sum(counts.values())}")
    print(f"events_per_second: {sum(counts.values()) / elapsed:.3f}")
    print(f"collector_cpu_one_core_percent: {cpu_seconds / elapsed * 100:.3f}")
    print(f"collector_peak_rss_bytes: {peak_rss}")
    print(f"collector_queue_overflow: {overflow}")
    print("counts_by_type:")
    for event_type, count in sorted(counts.items()):
        print(f"  {event_type}: {count}")
    for source in sources:
        for key, value in source.loss_counters().items():
            print(f"{key}: {value if value is not None else 'not measured'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
