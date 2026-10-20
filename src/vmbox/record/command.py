"""Windows VM entry point for live Sysmon recording."""

import platform
import sys
from pathlib import Path

from vmbox.anchor.receipt_crypto import load_public_key
from vmbox.anchor.transport import read_auth_key
from vmbox.collect.capture import capture_sysmon_trace, make_sysmon_header
from vmbox.collect.sysmon import SysmonSource
from vmbox.eval.policies import PolicyStrategy
from vmbox.record.live import LiveRecorder


def record_sysmon(*, output: Path, duration_s: float, strategy_name: str,
                  budget_bytes: int, journal_bytes: int, segment_events: int,
                  queue_capacity: int, sysmon_config: Path, anchor_endpoint: str,
                  anchor_pubkey: Path, anchor_auth_key: Path,
                  trace_path: Path | None = None) -> tuple[str, int, int, int]:
    """Return trace hash, events seen, collector overflow, pending checkpoints."""
    if sys.platform != "win32":
        raise RuntimeError("live recording must run on the isolated Windows VM")
    if duration_s <= 0:
        raise ValueError("duration must be positive")
    import psutil  # type: ignore[import-untyped]

    config = sysmon_config.read_bytes()
    public = load_public_key(anchor_pubkey)
    auth = read_auth_key(anchor_auth_key)
    strategy = PolicyStrategy(strategy_name)  # type: ignore[arg-type]
    boot_id = f"boot-{int(psutil.boot_time() * 1_000_000_000)}"
    header = make_sysmon_header(config, boot_id, platform.version(), queue_capacity)
    recorder = LiveRecorder(
        output, header, strategy, budget_bytes=budget_bytes,
        journal_bytes=journal_bytes, segment_events=segment_events,
        anchor_endpoint=anchor_endpoint, anchor_public_key=public,
        anchor_auth_key=auth, host=platform.node(),
    )
    path = trace_path or output / "raw_trace.jsonl"
    digest, overflow = capture_sysmon_trace(
        path, SysmonSource(), duration_s=duration_s, sysmon_config=config,
        boot_id=boot_id, windows_build=platform.version(),
        queue_capacity=queue_capacity, header=header, on_record=recorder.on_record,
        on_idle=recorder.on_idle, emit_lifecycle=True,
        stop_extra=lambda: {"anchor_outages": recorder.anchor_outages},
        on_ready=lambda: print("record_ready: start workload in terminal B", flush=True),
    )
    result = recorder.finish()
    return digest, recorder.events_seen, overflow, result.pending_segments
