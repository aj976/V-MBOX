# V-MBOX operator demo: start to report

This is the short two-VM workflow for the existing lab. **VMBOX-ANCHOR**
(`192.168.189.129`) signs and stores receipt history. **AJJJ**
(`192.168.189.128`) records Sysmon events and stores the evidence. Keep the
anchor window open through `finalize` and `report`.

## One-time setup

The updated code must be present in both `C:\VmboxLab\479a15e7-d7a17fe0\repo`
checkouts. `vmbox --help` must list `profile` and `finalize`. The prepared
Python environment, existing anchor keys, and isolated VM network are reused.
After these changes are pushed, `git pull` can update a VM checkout. A profile
still needs to be created separately under each VM user's account.

Save a profile once on **VMBOX-ANCHOR**:

```powershell
$root = 'C:\VmboxLab\479a15e7-d7a17fe0'
Set-Location "$root\repo"
$env:PATH = "$root\venv\Scripts;$env:PATH"
vmbox profile set demo --role anchor --lab-root $root --trial 89982d6f --endpoint 192.168.189.129:8765
```

Save a profile once on **AJJJ**:

```powershell
$root = 'C:\VmboxLab\479a15e7-d7a17fe0'
Set-Location "$root\repo"
$env:PATH = "$root\venv\Scripts;$env:PATH"
vmbox profile set demo --role monitored --lab-root $root --trial 89982d6f --endpoint 192.168.189.129:8765
sysmon64 -c .\docs\sysmon.xml
```

Profiles are write-once. If `profile set` says it already exists, skip it on
later runs. Profiles contain paths and the anchor address, not private keys.

## Every demo run

### 1. Start the anchor (VMBOX-ANCHOR, terminal A)

```powershell
$root = 'C:\VmboxLab\479a15e7-d7a17fe0'
Set-Location "$root\repo"
$env:PATH = "$root\venv\Scripts;$env:PATH"
vmbox anchor start
```

Wait for `anchor_listening: 192.168.189.129:8765`. Leave this window open.
If an earlier anchor listener is still running, use it instead of starting
another on the same port.

### 2. Record on AJJJ (terminal A)

```powershell
$root = 'C:\VmboxLab\479a15e7-d7a17fe0'
Set-Location "$root\repo"
$env:PATH = "$root\venv\Scripts;$env:PATH"
vmbox record --duration 60 --profile demo
```

Wait for `record_ready: start workload in terminal B`. The recorder chooses a
new evidence folder and prints it. You do **not** need to copy that path.
The demo profile uses context-aware selection, a 12 MiB total budget, an
8 MiB journal, and 128-event segments.

### 3. Generate benign activity on AJJJ (terminal B)

Open a second PowerShell on **AJJJ** while terminal A is recording:

```powershell
$root = 'C:\VmboxLab\479a15e7-d7a17fe0'
Set-Location "$root\repo"
& "$root\venv\Scripts\python.exe" .\scenarios\benign_noise.py --duration 30 --interval 0.2
```

This creates ordinary short-lived process and loopback-network activity.
Return to terminal A and let the 60-second recorder finish **naturally**;
do not press Ctrl+C.

### 4. Confirm receipts and open the report (AJJJ, terminal A)

```powershell
vmbox finalize
vmbox report --open
```

Both commands print the selected `evidence:` path. `finalize` sends pending
checkpoints, fetches an anchor-signed receipt snapshot, and compares anchor
and host histories. The report command creates `report.json` and
`report.html` beside the evidence and opens the HTML in the default browser.
The newest matching session is selected automatically, including a session
recorded before this shortcut was installed. For an older session, add
`--evidence C:\path\to\that\session`.

Export and report folders are write-once. For a repeat attempt, use a new
`--out` path rather than overwriting them. An anchor outage or incomplete
evidence must not be presented as a complete run. The new cross-VM shortcuts
are **unverified until run on both Windows VMs**. The anchor transport is
intended only for the isolated lab network.
