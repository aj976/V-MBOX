# M1 findings — spike 1, user-reported Windows VM output

This is a record of the terminal output supplied by the VM operator, not an independently reproduced run. The two benign workload outputs (118 and 113 iterations) were supplied together; which one overlapped this spike is not yet established. No final M1 event-set or collector decision is made here.

## Run identity

- VM snapshot: not measured
- Windows build: not measured
- Python, pywintrace, pywin32, Sysmon versions: not measured
- Sysmon config hash: not measured
- Git commit and dirty state on VM: not measured
- Spike command: `python .\scripts\m1_spike.py --duration 40 --sources both --etw-process-guid $processGuid --etw-network-guid $networkGuid`
- Reported duration: 52.657 seconds (40 seconds requested)
- Workload command: `python .\scenarios\benign_noise.py --duration 30 --interval 0.2`; outputs supplied: 118 and 113 completed iterations; pairing with this spike not established
- Output/log location: pasted into chat; VM file location not measured

## Observed event set

| Source and event type | Count |
|---|---:|
| `etw_kernel_network:KERNEL_NETWORK_TASK_TCPIP` | 702 |
| `etw_kernel_network:KERNEL_NETWORK_TASK_UDPIP` | 190 |
| `etw_kernel_process:CPUBASEPRIORITYCHANGE` | 2488 |
| `etw_kernel_process:CPUPRIORITYCHANGE` | 2449 |
| `etw_kernel_process:IMAGELOAD` | 1180 |
| `etw_kernel_process:IMAGEUNLOAD` | 1111 |
| `etw_kernel_process:IOPRIORITYCHANGE` | 21 |
| `etw_kernel_process:JOBSTART` | 17 |
| `etw_kernel_process:JOBTERMINATE` | 12 |
| `etw_kernel_process:PAGEPRIORITYCHANGE` | 135 |
| `etw_kernel_process:PROCESSFREEZE` | 8 |
| `etw_kernel_process:PROCESSSTART` | 20 |
| `etw_kernel_process:PROCESSSTOP` | 19 |
| `etw_kernel_process:PSDISKIOATTRIBUTION` | 8 |
| `etw_kernel_process:THREADSTART` | 514 |
| `etw_kernel_process:THREADSTOP` | 493 |
| `etw_kernel_process:THREADWORKONBEHALFUPDATE` | 34380 |
| `sysmon:MEM_IMAGE_LOAD` | 2499 |
| `sysmon:MEM_PROCESS_ACCESS` | 1498 |
| `sysmon:NET_CONNECT` | 229 |
| `sysmon:PROC_EXIT` | 116 |
| `sysmon:PROC_START` | 115 |

Sysmon event ID 8 (`MEM_REMOTE_THREAD`): no event shown in this output; this benign workload does not generate a remote thread. Memory-protection-change source: not measured. Sanitized parser fixtures: not measured.

## Rate and loss

- Events accepted/count reported by spike: 48,204
- Reported events per second: 915.429
- ETW events lost: 0; ETW log buffers lost: 0; ETW realtime buffers lost: 0
- Collector queue overflow: 2,302 (events dropped inside this collector)
- Sysmon upstream loss: not measured
- Script-generated versus observed process/network events: not measured; overlap and background activity are not isolated

## Collector overhead

- Collector CPU, one-core percent: 99.078
- Collector peak RSS: 32,972,800 bytes
- Workload baseline without collector: not measured

## Provisional interpretation

This run is not lossless: the collector reported 2,302 queue overflows despite zero ETW loss counters. The ETW process stream includes 34,380 `THREADWORKONBEHALFUPDATE` events, a major contributor to the measured load. The 52.657-second reported duration exceeds the requested 40 seconds; the current script times startup, shutdown, and queue draining in its elapsed measurement, so this output alone does not isolate steady-state capture rate. Repeat or refine measurement before a Python collector go/no-go decision. The second scripted scenario and memory-event set remain not measured.
