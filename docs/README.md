# V-MBOX — Volatile Memory Trace Recorder

A software-only forensic trace recorder for Windows. It collects selected process, memory-related, and network events, keeps the most investigation-relevant ones under a fixed storage budget, protects them with a tamper-evident hash chain, and rebuilds a qualified timeline after a crash or unexpected shutdown.

**Status:** M0 foundation implemented locally. M1 telemetry spike scripts are ready but unverified until run on a Windows VM. M2 and later are planned.

## What it is

- A trace recorder: it stores event *metadata*, not RAM contents.
- A research project: the core question is whether **context-aware evidence selection** preserves more attack-relevant evidence than fixed-policy or priority-based recording under the same storage budget.
- A complement to memory acquisition, EDR and endpoint telemetry, not a replacement.

## What it is not

- Not a RAM imager.
- Not a detector. It never declares that something is malicious, only that something was observed.
- Not hardware. The embedded-recorder phase of the original spec is out of scope.
- Not tamper-proof against a fully compromised host (see `DESIGN.md`, threat model).


## Planned layout

```
vmbox/
  src/vmbox/
    collect/      # telemetry sources (ETW, Sysmon, replay)
    normalize/    # raw -> schema records
    select/       # fixed, priority, context-aware strategies
    store/        # journal, sealed segments, eviction
    integrity/    # hash chain, checkpoints, verification
    anchor/       # off-host checkpoint service
    recover/      # post-crash recovery
    reconstruct/  # timelines, correlation
    report/       # report generation
    eval/         # replay harness, metrics, scenarios
    cli.py
  scenarios/      # scripted attack-like and benign workloads
  tests/
  docs/
```

## Planned CLI

```
vmbox record     # start collection + persistence
vmbox anchor     # run the off-host checkpoint service
vmbox verify     # check stored evidence against the chain and anchor receipts
vmbox recover    # inspect surviving evidence after a crash
vmbox timeline   # reconstruct a timeline
vmbox report     # generate the forensic report
vmbox eval       # replay traces through strategies and compute metrics
```

## Known limitations (up front)

- Windows exposes less memory telemetry to non-privileged consumers than Linux does. The memory category is limited to what is actually observable and is documented as such.
- Integrity is not authenticity: a compromised collector can feed fabricated events that are then stored faithfully.
- Results come from a lab VM with scripted scenarios. They show relative strategy performance under those conditions, nothing more.
