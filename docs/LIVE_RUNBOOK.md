# Live recorder and anchor validation (isolated Windows VMs)

This is an **unverified until run on both Windows VMs** procedure. It creates
new write-once evidence; choose fresh output names for every attempt. Keep the
existing M5/M6 trace, frozen labels, and results unchanged. Only lab VMs that
you own may be used. Never place `private.pem` on the monitored VM.

Before changing either VM, the laptop can run `scripts/lab_vm_preflight.ps1`
from Windows PowerShell. It prompts for credentials locally, reads each VM's
identity, repository revision, Python, and Sysmon version, then closes both
remote sessions. It does not save passwords or create evidence.
For cloned VMs whose Microsoft-account login cannot authenticate over WinRM,
run `scripts/lab_remote_account.ps1` once in Administrator PowerShell on each
VM. It creates a separate, expiring local `vmboxlab` administrator account for
the isolated lab; the preflight uses that account by default. The account is
removed after testing with `scripts/lab_remote_account.ps1 -Remove` on each VM.

If preflight shows that `vmboxlab` can run Python but cannot import the
project packages, or Git cannot read the cloned OneDrive checkout, run
`scripts/lab_vm_prepare.ps1` on the laptop. It prompts for the two lab-account
passwords locally, clones the same pinned Git revision into a new
`C:\VmboxLab\<revision>-<random>\repo` directory on each VM, and installs a
virtual environment beside it. The monitored VM gets the Windows collector
extras; the anchor VM gets the base package. The script never replaces an
existing lab directory. Keep its printed `lab_root`, checkout, and Python paths
for the live-test commands below; use those paths instead of the OneDrive
checkout or a bare `python` command. If setup fails, the partial directory is
left visible and a retry gets a new name. This preparation does not generate
evidence or anchor keys.

After preparation, run `scripts/lab_anchor_setup.ps1 -LabRoot <printed-lab-root>`
on the laptop. It generates a new key pair on the anchor VM, transfers only
`public.pem` and `auth.key` to the monitored VM through the existing authenticated
WinRM sessions, and opens anchor TCP port 8765 only to the monitored VM IP.
The script prints new key, ledger, and evidence paths. Keep those exact paths
for the listener and recorder commands. It does not start either process.

On the **anchor VM**, clone the repository and install the project as in
`README.md`. Create keys once and start the listener on the IP of its isolated
VM network adapter (substitute the real address):

```powershell
python -m vmbox.cli anchor-keygen --out C:\vmbox-anchor-keys
$anchorIp = '<anchor-VM-isolated-IP>'
python -m vmbox.cli anchor --listen "$($anchorIp):8765" --key C:\vmbox-anchor-keys\private.pem --auth-key C:\vmbox-anchor-keys\auth.key --store C:\vmbox-anchor-ledger
```

Copy only `public.pem` and `auth.key` to a private folder on the **monitored
VM**, through an isolated transfer channel. The shared auth key grants the
ability to submit checkpoints, so do not commit it or expose the listener to
the public network. Permit inbound TCP 8765 only from the monitored VM.

On the monitored VM, after `git pull origin main`, ensure Sysmon is installed
and apply the minimal config. Replace the IP and key paths with your actual
values. Run this in terminal A; start a benign workload in terminal B only after
`record_ready` prints. The raw trace is written inside the new evidence folder
unless `--tee-raw` names another new `.jsonl` path.

```powershell
cd C:\Users\aatmi\OneDrive\Desktop\vmbox
sysmon64 -c .\docs\sysmon.xml
$anchorIp = '<anchor-VM-isolated-IP>'
python -m vmbox.cli record --duration 40 --strategy context_aware --budget-bytes 12582912 --journal-bytes 8388608 --segment-events 128 --out .\runs\live_probe_1 --sysmon-config .\docs\sysmon.xml --anchor-endpoint "$($anchorIp):8765" --anchor-pubkey C:\vmbox-anchor-public\public.pem --anchor-auth-key C:\vmbox-anchor-public\auth.key
```

An exit code of 0 means the recorder finished without a measured collector
queue overflow and with no pending host receipts. It does **not** establish
source completeness or confirm the anchor's latest state. Exit 3 means pending
receipts or measured collector overflow; exit 2 means an error and any output
must be treated as incomplete. Sysmon upstream loss remains **not measured**.

After the listener is reachable, retry pending receipts without changing any
sealed evidence. Export a **copy** of `C:\vmbox-anchor-ledger` from the anchor
VM into a fresh directory on the monitored VM, then compare both receipt logs:

For the two-VM lab prepared with `lab_anchor_setup.ps1`, run
`scripts/lab_anchor_export.ps1 -LabRoot <printed-lab-root> -Trial <printed-trial>`
on the laptop after the recorder finishes. It reads the session ID from the
host manifest, transfers only the matching anchor receipt files through
authenticated WinRM, checks their SHA-256 hashes after transfer, and writes a
new `anchor_export_<trial>` directory on the monitored VM. It refuses to
overwrite an earlier export. Pass that printed directory to
`--anchor-receipts` in `verify`, `recover`, and `report`.

```powershell
python -m vmbox.cli anchor-sync --evidence .\runs\live_probe_1 --anchor-pubkey C:\vmbox-anchor-public\public.pem --anchor-auth-key C:\vmbox-anchor-public\auth.key
python -m vmbox.cli verify --evidence .\runs\live_probe_1 --anchor-pubkey C:\vmbox-anchor-public\public.pem --anchor-receipts C:\vmbox-anchor-export
python -m vmbox.cli recover --evidence .\runs\live_probe_1 --anchor-pubkey C:\vmbox-anchor-public\public.pem --anchor-receipts C:\vmbox-anchor-export
```

The live collector currently batches selection in 128-event windows. Context
promotion for batch selection uses only that batch; eviction scoring uses the
most recent 8192 observed events. It cannot retroactively change a prior sealed
batch, and context outside that bounded history no longer affects eviction.
The journal is flushed at 32 events or after an idle interval. These timing and
memory characteristics are **unverified until measured on the Windows VM**. Do
not merge live and offline strategy results as if their selection timing were
identical.

Before any crash injection, make a VM snapshot. A forced-kill or power-off run
must use a new evidence directory. Inspect recovery and report exit codes,
surviving frames, tombstones, and anchor-side receipt export. Do not populate
crash-recovery or persistence-latency metrics until timed, repeated real runs
have produced archived data.
