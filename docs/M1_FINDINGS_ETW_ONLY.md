# M1 findings — ETW-only benign noise, user-reported Windows VM output

This records terminal output supplied by the VM operator. The benign workload ran concurrently and completed 112 process/loopback iterations. It was not independently reproduced here.

## Run identity

- Spike command: `python .\scripts\m1_spike.py --duration 40 --sources etw --etw-process-guid $processGuid --etw-network-guid $networkGuid`
- Provider GUIDs were obtained on the VM with `Get-WinEvent -ListProvider` for Kernel-Process and Kernel-Network; actual GUID values were not supplied
- Workload command: `python .\scenarios\benign_noise.py --duration 30 --interval 0.2`
- Requested spike duration: 40 seconds; reported duration: 71.028 seconds
- VM snapshot, Windows build, Python/pywintrace versions, VM Git commit/dirty state: not measured
- Output/log location: pasted into chat; VM file location not measured

## Observed counts

- `etw_kernel_network:KERNEL_NETWORK_TASK_TCPIP`: 1,930
- `etw_kernel_network:KERNEL_NETWORK_TASK_UDPIP`: 250
- `etw_kernel_process:CPUBASEPRIORITYCHANGE`: 940
- `etw_kernel_process:CPUPRIORITYCHANGE`: 2,260
- `etw_kernel_process:IMAGELOAD`: 600
- `etw_kernel_process:IMAGEUNLOAD`: 566
- `etw_kernel_process:IOPRIORITYCHANGE`: 20
- `etw_kernel_process:JOBSTART`: 3
- `etw_kernel_process:JOBTERMINATE`: 3
- `etw_kernel_process:PAGEPRIORITYCHANGE`: 220
- `etw_kernel_process:PROCESSFREEZE`: 2
- `etw_kernel_process:PROCESSSTART`: 5
- `etw_kernel_process:PROCESSSTOP`: 4
- `etw_kernel_process:PSDISKIOATTRIBUTION`: 2
- `etw_kernel_process:THREADSTART`: 422
- `etw_kernel_process:THREADSTOP`: 429
- `etw_kernel_process:THREADWORKONBEHALFUPDATE`: 32,729
- `etw_unknown:LOSTEVENT`: 1

## Rate and loss

- Events counted by spike: 40,386
- Reported events per second: 568.593
- Collector queue overflow: 20,377
- ETW events lost: 0; ETW log buffers lost: 0; ETW realtime buffers lost: 0
- `etw_unknown:LOSTEVENT` records: 1; its exact relationship to the zero ETW counters is not established
- Workload iterations: 112; event attribution is not established, and collector loss prevents a reliable one-to-one comparison

## Collector overhead

- Collector CPU, one-core percent: 94.637
- Collector peak RSS: 34,381,824 bytes
- Workload baseline without collector: not measured

## Provisional interpretation

The unfiltered ETW-only Python spike is not adequate at this observed load: it used most of one CPU core and overflowed its queue 20,377 times. The 32,729 `THREADWORKONBEHALFUPDATE` events dominate counted traffic. This run isolates the combined-run overload to the ETW path, but does not establish whether a narrower ETW subscription or a different collector implementation would meet the requirement. The reported duration includes startup, shutdown, and queue draining and exceeds the requested 40 seconds. Memory-protection-change availability remains unmeasured.
