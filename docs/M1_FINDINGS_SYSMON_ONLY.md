# M1 findings — Sysmon-only benign noise, user-reported Windows VM output

This records terminal output supplied by the VM operator. The benign workload ran concurrently and completed 119 process/loopback iterations. It was not independently reproduced here.

## Run identity

- Spike command: `python .\scripts\m1_spike.py --duration 40 --sources sysmon`
- Workload command: `python .\scenarios\benign_noise.py --duration 30 --interval 0.2`
- Requested spike duration: 40 seconds; reported duration: 40.052 seconds
- VM snapshot, Windows build, Python/pywin32/Sysmon versions, Sysmon config hash, VM Git commit/dirty state: not measured
- Output/log location: pasted into chat; VM file location not measured

## Observed counts

- `sysmon:MEM_IMAGE_LOAD`: 2,233
- `sysmon:MEM_PROCESS_ACCESS`: 1,697
- `sysmon:NET_CONNECT`: 234
- `sysmon:PROC_EXIT`: 123
- `sysmon:PROC_START`: 121
- Sysmon ID 8 (`MEM_REMOTE_THREAD`): no event shown; the workload does not create a remote thread
- Memory-protection-change source and sanitized parser fixtures: not measured

## Rate and loss

- Events counted by spike: 4,408
- Reported events per second: 110.056
- Collector queue overflow: 0
- Sysmon upstream loss: not measured
- Script iterations: 119; one-to-one attribution to observed process/network counts is not established because background events also appear

## Collector overhead

- Collector CPU, one-core percent: 1.873
- Collector peak RSS: 24,641,536 bytes
- Workload baseline without collector: not measured

## Provisional interpretation

At this observed rate, the Sysmon-only Python spike had no measured internal queue overflow and low measured collector CPU. This supports further testing of a filtered collection policy, but does not prove that Sysmon delivered every upstream event. The combined ETW+Sysmon runs overflowed the collector queue; an ETW-only run is needed to isolate ETW load before choosing the collection architecture. No final memory-event set or Python collector go/no-go decision is recorded yet.
