# M1 findings — template, not a measurement

Status: unverified until run on Windows VM. Copy this file to a run-specific findings file after recording real output. Keep "not measured" for every missing value.

## Run identity

- VM snapshot: not measured
- Windows build: not measured
- Python version: not measured
- pywintrace version: not measured
- pywin32 version: not measured
- Sysmon version and config hash: not measured
- Git commit and dirty state: not measured
- Command, duration, workload: not measured
- Output/log location: not measured

## Observed event set

- Kernel-Process process start/exit: not measured
- Kernel-Network connect/close: not measured
- Sysmon 1, 3, 5, 7, 8, 10: not measured
- Memory-protection-change source: not measured
- Sanitized real-event parser fixtures captured: not measured

## Rate and loss

- Counts by source and event type: not measured
- Events per second: not measured
- ETW events/buffers lost: not measured
- Collector queue overflow: not measured
- Sysmon upstream loss: not measured
- Script-generated vs observed process/network events: not measured

## Collector overhead

- Collector CPU (one-core percent): not measured
- Collector peak RSS bytes: not measured
- Workload baseline without collector: not measured

## Decision

- Memory-event set supported by measured observations: not measured
- Python collector go/no-go and basis: not measured
- DESIGN §3.1 update needed: not measured
- Limits, gaps, and follow-up checks: not measured
