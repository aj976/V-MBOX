# V-MBOX classroom demonstration

The working prototype has been exercised on two isolated Windows VMs. This
walkthrough shows the recorder, signed anchor receipts, and the resulting
integrity-qualified report. It does not claim malware detection or complete
source capture. Keep the anchor signing key on the anchor VM.

## What each VM does

- **Monitored VM:** subscribes to Sysmon, writes an unfiltered raw trace,
  assigns sequence numbers in arrival order, journals normalized events,
  applies a storage budget, and seals selected events in a local hash chain.
- **Anchor VM:** receives checkpoints for sealed segments and returns signed,
  per-session chained receipts. Its ledger is separate from the monitored VM.

The flow is `Sysmon → raw trace → normalizer → journal → selector → sealed
segments → anchor receipts → verify/recover/report`. A missing event upstream
of Sysmon cannot be recovered by the recorder. The tool records observations
and integrity limits; it does not decide intent.

## Before class

1. Start both VMs on their isolated network. Use the prepared, non-synced
   lab checkout and virtual environment; do not run from a OneDrive folder.
2. On the anchor VM, start `vmbox.cli anchor` with the existing key and ledger.
   Wait for `anchor_listening` and keep that window open.
3. On the monitored VM, check the listener with
   `Test-NetConnection <anchor-ip> -Port 8765`; it should report
   `TcpTestSucceeded : True`.
4. Preserve the two previously completed evidence directories. A new recording
   needs a fresh `--out` name; evidence is write-once.

## Short demonstration using existing evidence

On the monitored VM, set these values to the prepared lab paths and run the
commands. The anchor export must be the one for the **same session** as the
host evidence.

```powershell
$py = '<lab-root>\venv\Scripts\python.exe'
$evidence = '<lab-root>\live_<trial>'
$public = '<lab-root>\anchor_public_<trial>\public.pem'
$anchorExport = '<lab-root>\anchor_export_<trial>'
& $py -m vmbox.cli verify --evidence $evidence --anchor-pubkey $public --anchor-receipts $anchorExport
& $py -m vmbox.cli recover --evidence $evidence --anchor-pubkey $public --anchor-receipts $anchorExport
```

`verify` checks the local segment chain, receipt signatures, and the anchor
export. `recover` reports surviving events, gaps, tombstones, and receipt
status. `journal: readable, unverified` means CRC-readable journal frames do
not by themselves have the sealed segment's cryptographic integrity level.
An `anchored` event has a sealed segment covered by a verified receipt. A
`chained` event has a locally verified segment without a confirmed receipt.

Open an already generated `report.html` next to its `report.json`, or create a
new report in a fresh output directory:

```powershell
& $py -m vmbox.cli report --evidence $evidence --out '<fresh-report-directory>' --anchor-pubkey $public --anchor-receipts $anchorExport
```

Show the visible report content hash and integrity counts. The HTML is a view
of the JSON report, so its claims should be checked against that file. An
offline-evaluation report is labeled as such and is not forensic evidence.

## Optional live capture

With the anchor listener running, on the monitored VM start `vmbox.cli record`
using the prepared public key and shared auth key, a fresh evidence directory,
and a finite duration. After `record_ready`, start the benign workload in a
second window. The recorder prints the raw-trace hash, event count, measured
collector queue overflow, and pending anchor segments. Export that session's
anchor receipts to a new directory, then run `verify` and `recover` as above.
See `LIVE_RUNBOOK.md` for the exact command shape and key-transfer procedure.

An anchor outage is a useful second demonstration: the recorder continues
locally, reports pending segments, and exits 3. After the anchor restarts,
`anchor-sync` retries the same checkpoints. A fresh anchor receipt export then
confirms the session. Do not describe an unconfirmed host-only range as
anchored.

## Claims and limits to say aloud

- V-MBOX records **observed Windows telemetry** and preserves selected records
  with integrity levels. It does not identify malware or intent.
- A successful hash-chain and receipt check detects changes to covered
  evidence after sealing. It cannot prove that Sysmon observed every action or
  that the collector was honest before sealing.
- Queue overflow is measured by this collector; Sysmon upstream loss is not
  measured in the current live run. Missing and unmeasured values stay
  explicit, never silently become zero.
- The first two-VM live and outage/retry trials succeeded. Forced-stop,
  power-off, persistence-latency, and independent multi-trace statistical
  claims require further archived VM runs.
