# M1 findings — spike 2, user-reported Windows VM output

This records the VM operator's pasted spike output; it was not independently reproduced here. The spike command and matching scenario output were not supplied, so workload overlap remains unconfirmed. No final event-set decision is made from this output alone.

## Run identity

- VM snapshot, Windows build, dependency versions, Sysmon config hash, VM Git commit/dirty state: not measured
- Spike command and requested duration: not measured
- Reported duration: 34.711 seconds
- Matching scenario command and output: not measured
- Output/log location: pasted into chat; VM file location not measured

## Observed counts

- `etw_kernel_network:KERNEL_NETWORK_TASK_TCPIP`: 621
- `etw_kernel_network:KERNEL_NETWORK_TASK_UDPIP`: 119
- `etw_kernel_process:CPUBASEPRIORITYCHANGE`: 2092
- `etw_kernel_process:CPUPRIORITYCHANGE`: 1458
- `etw_kernel_process:IMAGELOAD`: 731
- `etw_kernel_process:IMAGEUNLOAD`: 783
- `etw_kernel_process:IOPRIORITYCHANGE`: 16
- `etw_kernel_process:JOBSTART`: 18
- `etw_kernel_process:JOBTERMINATE`: 10
- `etw_kernel_process:PAGEPRIORITYCHANGE`: 74
- `etw_kernel_process:PROCESSFREEZE`: 8
- `etw_kernel_process:PROCESSSTART`: 15
- `etw_kernel_process:PROCESSSTOP`: 16
- `etw_kernel_process:PSDISKIOATTRIBUTION`: 8
- `etw_kernel_process:THREADSTART`: 265
- `etw_kernel_process:THREADSTOP`: 267
- `etw_kernel_process:THREADWORKONBEHALFUPDATE`: 16735
- `etw_unknown:LOSTEVENT`: 1
- `sysmon:MEM_IMAGE_LOAD`: 194
- `sysmon:MEM_PROCESS_ACCESS`: 245
- `sysmon:NET_CONNECT`: 6
- `sysmon:PROC_EXIT`: 4
- `sysmon:PROC_START`: 4
- Sysmon ID 8 (`MEM_REMOTE_THREAD`): no event shown in this output; scenario overlap not confirmed
- Memory-protection-change source and sanitized parser fixtures: not measured

## Rate and loss

- Events counted by spike: 23,690
- Reported events per second: 682.502
- Collector queue overflow: 3,445
- ETW events lost: 0; ETW log buffers lost: 0; ETW realtime buffers lost: 0
- `etw_unknown:LOSTEVENT` records: 1; its exact relationship to the zero ETW counters is not established
- Sysmon upstream loss: not measured
- Script-generated versus observed events: not measured

## Collector overhead

- Collector CPU, one-core percent: 91.831
- Collector peak RSS: 35,418,112 bytes
- Workload baseline without collector: not measured

## Provisional interpretation

This run is not lossless: 3,445 events overflowed the collector queue. The process stream contains 16,735 `THREADWORKONBEHALFUPDATE` events, and the collector used 91.831% of one CPU core. The current unfiltered Python spike cannot be accepted as a lossless collector at this observed load. This does not decide whether a filtered Python collector, changed ETW subscription, or a native hot path would meet the requirement. The `LOSTEVENT` record requires investigation before treating the ETW zero counters as complete loss evidence. The memory proxy set and any `MEM_PROTECT_CHANGE` source remain unresolved.
