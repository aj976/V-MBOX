# V-MBOX reproducibility and completion status

This is a status record, not a claim that the experiment or live recorder has
passed its final acceptance criteria. Evidence schema version remains 1.

## Implemented software

- M0-M4: canonical formats, replayable raw trace, journal and sealed segments,
  tombstones, local chain verification, and signed per-session anchor receipts.
- M5-M8: frozen scenario labels and review, offline strategy replay, budgeted
  retention, recovery/report generation, paired aggregate statistics, and a
  matrix runner that records attempted and failed runs.
- M9: synthetic trust-boundary probes for pre-seal changes, full local chain
  rewrites, missing host receipts, and byte corruption.
- Live path: Sysmon-only recorder and authenticated checkpoint transport. Live
  selection is batch-local; the eviction scorer considers at most the latest
  8192 observed events. It is not the same experiment as whole-trace replay.

## Archived inputs and reproducibility

The single reported `query_connect` seed-1 trace has exact-byte hash
`sha256:9fb805f41622bf8af07d4652abd0f14fdfdd063acfd766d7e5c3f76bde041607`.
Its frozen labels have hash
`sha256:89e9050ccc2a09518d30c2d948a3bd5bff8b00330100d0818dad6707c7ff2602`.
These hashes came from the operator's Windows VM outputs; this checkout does not
contain the full raw trace, labels, or all 17 replay directories. The M6
unbounded reference retained 11,272,443 bytes in that operator run. The 16
budgeted results used the same trace, so they are **one independent sample**.
The M8 aggregate reported 17 completed attempts and 880 inconclusive
comparisons with `n=1` in each group. These are operator-reported outputs, not
independently reproduced from archived inputs in this checkout.

To reproduce on the VM, keep the original trace and frozen labels unchanged,
then use `M8_RUNBOOK.md` to create fresh write-once replay directories and an
aggregate. New independent traces require their own nonce, frozen labels, and
run inventory. The aggregate's `content_hash` permits deterministic checking
after excluding `generated_at`; tables must be generated from the validated
aggregate, not copied from console text.

## Claims the current data support

The measured M1 unfiltered ETW spike overflowed the Python collector queue;
the Sysmon-only run reported no collector queue overflow. Sysmon upstream loss
was **not measured**. The available frozen query/connect scenario had three
collected labeled steps, but it supplies no complete relation ground truth.
Offline replay verification reported a readable journal and valid local chain;
budgeted reports showed tombstones and correctly classified journal-only
events. Offline sessions are not forensic evidence and have no off-host anchor.

## Remaining acceptance work

1. Run `LIVE_RUNBOOK.md` on the monitored VM with an independent anchor key and
   receipt store on the second VM. Archive both host evidence and anchor export.
   Live Sysmon behavior, checkpoint delivery, overflow, memory, and latency are
   **unverified until run on Windows VMs**.
2. Perform controlled forced-process termination, power-off recovery, anchor
   outage, and copied-evidence tamper tests. Record actual exit codes, gaps,
   receipt differences, and surviving committed events. Crash-recovery rate
   and persistence-latency percentiles remain **not measured**.
3. Capture independently varying traces for tuning and held-out scenario sets.
   Run the same budget matrix per trace and aggregate by trace, with paired
   differences and the configured minimum `n`. No strategy superiority claim
   follows from the current one-trace results.
4. Archive the exact source revision, raw traces and sidecars, Sysmon config,
   frozen labels and reviews, lockfile, per-run results, attempt inventories,
   anchor public key, anchor export, and generated reports. Keep raw-command-line
   opt-in traces local and out of the repository.
5. Write the final related-work and result discussion from verified sources and
   archived measurements. Do not fill null metrics from an estimate or a test
   fixture.

The main limits remain host-controlled telemetry and timestamps, memory-event
proxies rather than full memory visibility, unmeasured Sysmon upstream loss,
batch-local live selection, and no protection against fabrication or suppression
before a segment is sealed. A signed receipt constrains changes to an already
anchored segment; it does not establish that the original observation was true.
