"""Capture a Sysmon-only M5 raw trace in the isolated Windows VM."""

import argparse
import platform
import sys
from pathlib import Path

from vmbox.collect.capture import capture_sysmon_trace
from vmbox.collect.sysmon import SysmonSource


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sysmon-config", type=Path, default=Path("docs/sysmon.xml"))
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("run only in the isolated Windows VM")
    import psutil

    digest, overflow = capture_sysmon_trace(
        args.out, SysmonSource(), duration_s=args.duration,
        sysmon_config=args.sysmon_config.read_bytes(),
        boot_id=f"boot-{int(psutil.boot_time() * 1_000_000_000)}",
        windows_build=platform.version(),
        on_ready=lambda: print("capture_ready: start scenario in terminal B", flush=True),
    )
    print(f"trace_hash: {digest}")
    print(f"collector_queue_overflow: {overflow}")
    print("sysmon_upstream_lost: not measured")
    print(f"trace_file: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
