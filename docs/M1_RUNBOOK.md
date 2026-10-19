# M1 Windows VM runbook

This spike is **unverified until run on Windows VM**. Use your own isolated lab VM and a clean snapshot. No M2 recorder, normalizer, or persistence is included. The workload uses only local processes and loopback traffic; it does not create a remote thread or modify another process's memory. Therefore absence of Sysmon 8 is expected from this workload, not evidence that the source is unavailable.

Open PowerShell as Administrator in the repo root. Install Python 3.11+ and Sysmon first. The commands below assume `python`, `sysmon64`, and `logman` are on `PATH`.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,windows]"
python -m pytest
python -m ruff check .
python -m mypy src/vmbox
sysmon64 -s
sysmon64 -i .\docs\sysmon.xml
```

If Sysmon is already installed, use `sysmon64 -c .\docs\sysmon.xml` instead of `-i`. Confirm the VM's Sysmon schema accepts this config and inspect `sysmon64 -c`. Sysmon IDs 4, 16, and error 255 are unfilterable, so "only six IDs" applies to configurable event classes. [Microsoft's Sysmon reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) documents the config tags and `-s` command.

Each selected class uses an empty `exclude` filter, which includes all events of that class. Image-load and process-access volume may be high; record the rate before narrowing the M2 collection policy.

Discover provider GUIDs on **this VM**; do not copy guessed GUIDs from another machine:

```powershell
logman query providers "Microsoft-Windows-Kernel-Process"
logman query providers "Microsoft-Windows-Kernel-Network"
$processGuid = (Get-WinEvent -ListProvider 'Microsoft-Windows-Kernel-Process').Id.ToString('B')
$networkGuid = (Get-WinEvent -ListProvider 'Microsoft-Windows-Kernel-Network').Id.ToString('B')
$processGuid
$networkGuid
```

If either provider is absent or GUID discovery fails, record the command and error in findings; run `--sources sysmon` alone. The ETW source follows [pywintrace's callback/start/stop API](https://github.com/fireeye/pywintrace) and its kernel-process test, but the two-provider combination and returned loss counters are unverified until this VM run. The Sysmon source follows [pywin32's pull subscription example](https://github.com/mhammond/pywin32/blob/main/win32/Demos/EvtSubscribe_pull.py).

Use two elevated PowerShell terminals. Start the spike first in terminal A; start each workload promptly in terminal B. Save the terminal output in your own run directory, not as a fabricated repo result.

Terminal A, benign noise:

```powershell
python .\scripts\m1_spike.py --duration 40 --sources both --etw-process-guid $processGuid --etw-network-guid $networkGuid
```

Terminal B, benign noise:

```powershell
python .\scenarios\benign_noise.py --duration 30 --interval 0.2
```

Repeat for the scripted injection-like sequence (still only benign behavior):

```powershell
python .\scripts\m1_spike.py --duration 20 --sources both --etw-process-guid $processGuid --etw-network-guid $networkGuid
```

```powershell
python .\scenarios\injection_like_simulation.py --duration 10
```

The spike prints counts by type, total rate, queue overflow, ETW loss counters when pywintrace exposes them, collector CPU time as one-core percent, and peak RSS. `not measured` for a loss counter means no verified API value was available; never read it as zero. Compare process/network counts with workload actions and inspect Sysmon Operational for source errors. Run Sysmon-only if the ETW path fails:

```powershell
python .\scripts\m1_spike.py --duration 40 --sources sysmon
```

For the memory-protection-change decision, verify available providers on the VM (`logman query providers`) and document access requirements and a real capture if one is possible. Do not add `MEM_PROTECT_CHANGE` from a provider name alone. Fill [M1_FINDINGS.md](M1_FINDINGS.md) only from recorded runs, then update DESIGN §3.1 with the measured event set and Python go/no-go decision.
