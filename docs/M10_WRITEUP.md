# V-MBOX study outline and methodology

This document describes the implemented design and the planned evaluation. It
is not a final results paper. The current evidence supports only the narrow
observations in `M10_STATUS.md`.

## Research question and scope

V-MBOX asks whether context-aware retention preserves more labeled,
investigation-relevant Windows event metadata than fixed, priority, and FIFO
policies at the same total storage budget. It records event metadata rather
than memory contents and makes no detection, attribution, or intent claim.
The experiment uses benign scripted behavior on isolated lab VMs. An event
label identifies the scenario step that produced it, not a judgment about an
arbitrary machine or process.

## Architecture

The live path subscribes to Sysmon, records one write-once canonical JSON Lines
raw trace in arrival order, and normalizes each observed source event. The
normalizer assigns `seq` before selection and derives a stable event ID from
the session ID and sequence. A fixed-size CRC journal receives records before
the selector seals a batch. Each selected batch is written as an immutable
segment with a local hash chain; budget eviction replaces a segment with a
checksummed tombstone that retains its hash and bounds. The recorder submits
checkpoints to a separate anchor, which keeps its Ed25519 private key and
write-once receipt ledger off the monitored VM. Recovery validates the
journal, segment chain, tombstones, and available receipts before producing a
qualified timeline and report. See `DESIGN.md` and `SCHEMA.md` for the exact
format and integrity rules.

The offline evaluation path replays the same frozen trace through an unbounded
reference and four budgeted strategies. Replay is a controlled comparison,
not a live evidence session; its integrity is chained at best. Live selection
uses only current batches and a bounded recent scoring history, so its output
must be evaluated separately from whole-trace replay.

## Experimental method

Each scenario run begins with a unique marker that serves as the time anchor
for frozen label windows. The matcher requires event type, image identity, and
applicable PID lineage in addition to the inclusive relative time window.
Missing anchor or ambiguous anchors fail the run. Ambiguous candidate matches
are reviewed and frozen with reviewer provenance. A labeled step absent from
the raw trace is a collection miss; a step observed but absent from retained
evidence is a retention miss. The labels and policy rules are frozen before
held-out evaluation.

For each independent trace, replay every strategy at the same total budgets.
The budget includes journal, surviving sealed segments, and tombstones; it
excludes raw input traces and anchor receipts. The unbounded run supplies the
measured full-size denominator. Result files record trace, label, config,
revision, and tool provenance, and failed attempts remain in the inventory.
The independent statistical unit is the recorded trace, not a deterministic
replay or unchanged seed. Strategy comparisons are paired by trace. The
aggregate records the CI method, RNG seed, resample count, `n`, and the number
of unadjusted comparisons. Below the configured minimum independent `n`, the
CI is null and the verdict remains inconclusive. Tuning and held-out sets are
never pooled.

Live validation must measure collector queue overflow, upstream visibility
where available, CPU, memory, disk traffic, durable-write latency, and recovery
after controlled process termination and power loss. Anchor tests compare host
receipts with a separately exported anchor ledger. Unobserved or incomplete
data remain null; a valid local hash chain alone does not establish source
completeness or truth. `LIVE_RUNBOOK.md` and `M9_LOCAL_PROBES.md` separate real
VM checks from synthetic unit probes.

## Related work and distinction

[Volatility 3](https://volatility3.readthedocs.io/en/latest/) analyzes memory
images through plugins and memory layers. V-MBOX does not acquire or inspect a
RAM image; it keeps selected runtime metadata that may help reconstruct a
sequence when no image was taken. This is a complement, not an equivalent
memory-forensics technique.

[Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
defines the process, network, image-load, remote-thread, and process-access
event classes used in the collector. Image-load and process-access events are
proxies for some memory-related activity, not a complete account of memory
operations. [Microsoft's ETW overview](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
describes the provider/session model behind the separate M1 spike. The measured
unfiltered Python ETW collector overflowed its queue in that lab run; V-MBOX
therefore does not assume that subscription is a reliable live hot path.

[Schneier and Kelsey's secure audit log work](https://www.schneier.com/academic/archives/1999/05/secure_audit_logs_to.html)
motivates explicit treatment of post-compromise log modification. V-MBOX uses
a different, simpler construction: a local hash chain plus receipts signed by
an independent anchor. It does **not** implement forward-secure key evolution,
and it cannot detect an event fabricated or suppressed before sealing. The
off-host receipt protects only the already anchored range while the anchor key
and ledger remain independent and available.

## Interpretation limits

The reported data so far cover one independent trace and one scenario family.
They cannot establish an effect size or a strategy winner. Sysmon upstream loss,
relationship precision/recall, live latency, crash recovery, and second-VM
anchor behavior remain **not measured**. Results from new traces must include
collection coverage next to evidence coverage, gaps and tombstones next to
integrity claims, and the lab-only scope next to any comparison. A compromised
collector, manipulated host clock, missed source event, or compromised anchor
is outside the guarantees of a successfully verified local chain.
