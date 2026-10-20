# V-MBOX — Volatile Memory Trace Recorder

A software-only forensic trace recorder for Windows. It collects selected process, memory-related, and network events, keeps the most investigation-relevant ones under a fixed storage budget, protects them with a tamper-evident hash chain, and rebuilds a qualified timeline after a crash or unexpected shutdown.

**Status (2026-10-20):** The M1 Sysmon/ETW spike, one M5 trace, M6 offline replays, and M7 recovery/report checks have operator-reported Windows VM results in the linked runbooks. M8 aggregation of those results has one independent trace, so no confidence interval or strategy winner is established. A live Sysmon recorder and authenticated anchor transport now pass synthetic/loopback tests, but live capture, second-VM anchoring, process-kill/power-off recovery, and long-soak behavior are **unverified until run on the Windows VMs**.

## What it is

- A trace recorder: it stores event *metadata*, not RAM contents.
- A research project: the core question is whether **context-aware evidence selection** preserves more attack-relevant evidence than fixed-policy or priority-based recording under the same storage budget.
- A complement to memory acquisition, EDR and endpoint telemetry, not a replacement.

## What it is not

- Not a RAM imager.
- Not a detector. It never declares that something is malicious, only that something was observed.
- Not hardware. The embedded-recorder phase of the original spec is out of scope.
- Not tamper-proof against a fully compromised host (see `DESIGN.md`, threat model).


## Repository layout

```
vmbox/
  src/vmbox/
    collect/      # telemetry sources (ETW, Sysmon, replay)
    normalize/    # raw -> schema records
    eval/         # frozen-label replay, policies, metrics, aggregation
    store/        # journal, sealed segments, eviction
    integrity/    # hash chain, checkpoints, verification
    anchor/       # off-host checkpoint service
    record/       # live Sysmon recorder orchestration
    recover/      # post-crash recovery
    reconstruct/  # timelines, correlation
    report/       # reserved report package; renderer lives in reconstruct/
    cli.py
  scenarios/      # scripted attack-like and benign workloads
  tests/
  docs/
```

## CLI and runbooks

```
vmbox record     # start collection + persistence
vmbox anchor     # run the off-host checkpoint service
vmbox verify     # check stored evidence against the chain and anchor receipts
vmbox recover    # inspect surviving evidence after a crash
vmbox timeline   # reconstruct a timeline
vmbox report     # generate the forensic report
scripts/m5_eval.py / m6_eval.py / m8_aggregate.py  # replay and aggregate
```

Install from a fresh clone with Python 3.11+ using `python -m pip install -e .`.
Run unit checks with `python -m pytest -q`. See `M1_RUNBOOK.md` for telemetry,
`M5_RUNBOOK.md` through `M8_RUNBOOK.md` for frozen-label replay and derived
results, and `LIVE_RUNBOOK.md` for the two-VM recorder/anchor commands. Every
evidence output directory and result file is write-once; choose fresh names
for retries. Existing VM results remain on the operator's VM unless explicitly
archived and sanitized. Do not commit raw traces, keys, or unsanitized host data.

## Known limitations (up front)

- Windows exposes less memory telemetry to non-privileged consumers than Linux does. The memory category is limited to what is actually observable and is documented as such.
- Integrity is not authenticity: a compromised collector can feed fabricated events that are then stored faithfully.
- Results come from a lab VM with scripted scenarios. They show relative strategy performance under those conditions, nothing more.
