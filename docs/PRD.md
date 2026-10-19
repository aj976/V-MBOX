# PRD — V-MBOX

## 1. Summary

V-MBOX records selected, security-relevant traces of Windows system activity into bounded non-volatile storage so an investigator can reconstruct what happened after a crash, power loss, or unexpected shutdown. It is a software-only research prototype.

## 2. Problem

Evidence in volatile state disappears when a host fails. Conventional logging has gaps: events not collected, volatile buffers lost on crash, logs modifiable by privileged attackers, disconnected records with no relationship context, and high-volume logging that burns storage.

## 3. Goals

1. Collect process, memory-related, and network event metadata on Windows.
2. Normalize events into one schema that separates observed, derived, and inferred data.
3. Retain the most valuable evidence under a fixed storage budget, using three comparable strategies.
4. Make stored evidence tamper-evident and make gaps and incomplete writes visible.
5. Recover and verify surviving evidence after a crash.
6. Reconstruct timelines and produce a report that states its own limitations.
7. Evaluate the strategies reproducibly against ground truth.

## 4. Non-goals

- Hardware recorder, embedded firmware, external flash (dropped from the original spec).
- Full RAM acquisition or memory-image analysis.
- Malware detection, attribution, or proof of intent or exfiltration.
- Replacing EDR, Sysmon pipelines, or SIEMs.
- Linux or macOS support.
- Defending against an attacker with full control of the host and the off-host anchor.

## 5. Users

| User | Need |
|---|---|
| Incident responder / forensic investigator | A verifiable, qualified record of activity before a failure; clear statement of what is missing |
| Researcher (project author) | A reproducible framework to compare evidence-selection strategies |

## 6. Research question and hypothesis

**Question:** Can context-aware evidence selection preserve more attack-relevant evidence and enable more accurate post-incident reconstruction than fixed-policy or priority-based recording under equal storage budgets?

**Hypothesis:** It can, at tight budgets, without continuously storing all events. This is not assumed. A null or mixed result is a valid outcome and will be reported as is.

## 7. Functional requirements

| ID | Requirement |
|---|---|
| FR-1 | Collect process create/exit events with PID, PPID, image path, command line (where available), timestamp |
| FR-2 | Collect network connect/close events with endpoints, ports, protocol, PID association |
| FR-3 | Collect memory-related events limited to what is observable (see DESIGN §3.1); each carries its capture source |
| FR-4 | Normalize to the schema in `SCHEMA.md` with sequence numbers, boot/session IDs, capture status, collector version |
| FR-5 | Implement three strategies behind one interface: fixed-policy, priority-based, context-aware |
| FR-6 | Enforce a configurable total storage budget for retained evidence |
| FR-7 | Write a journal and sealed, hash-chained segments; never treat an incomplete write as complete |
| FR-8 | Send integrity checkpoints to an off-host anchor and store signed receipts |
| FR-9 | Detect and report sequence gaps, collector interruptions, dropped events, and tombstoned (evicted) segments |
| FR-10 | `verify` reports per-segment integrity status and chain/anchor consistency |
| FR-11 | `recover` works after forced termination of the collector or VM |
| FR-12 | `timeline` and `report` output chronological events, correlations, integrity results, gaps, and limitations |
| FR-13 | Every derived relationship carries a basis and a confidence label; nothing is stated as causal without basis |
| FR-14 | Replay harness runs any recorded raw trace through any strategy at any budget deterministically |
| FR-15 | Ground-truth labeling for scripted scenarios and metric computation (see §9) |

## 8. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | Collector overhead measured and reported (CPU, memory, disk I/O); no fixed target is promised before measurement |
| NFR-2 | Event-loss and persistence latency measured, not assumed |
| NFR-3 | Deterministic, seeded experiments; raw traces and configs archived |
| NFR-4 | Canonical serialization so hashes are reproducible across runs |
| NFR-5 | Fails loud: any component error becomes a recorded capture-status event where possible |

## 9. Evaluation

Metrics (definitions in `DESIGN.md` §8): evidence coverage, reconstruction accuracy, storage efficiency, event-loss rate, persistence latency, crash-recovery rate, system overhead.

Baselines: unbounded full log (upper bound), FIFO ring buffer of equal budget, fixed-policy, priority-based.

Method: scripted scenarios (attack-like sequences plus benign noise) in an isolated Windows VM; traces recorded once, replayed through strategies at several budgets across multiple seeds; report means with confidence intervals.

## 10. Success criteria

- **Functional:** the pipeline records, survives forced termination, recovers, verifies, and reports end to end.
- **Integrity:** tampering with a stored segment is detected in all tested modification cases; the documented limits are demonstrated, not just stated.
- **Research:** a documented comparison of the three strategies with honest effect sizes. Success does not require context-aware to win.

## 11. Assumptions

- Admin rights are available in a lab VM.
- Sysmon and ETW kernel providers are usable as telemetry sources.
- Scenarios are scripted simulations, run only in an isolated VM.

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Memory telemetry on Windows is too thin to form meaningful sequences | Weakens the context-aware story | Validate in M1; fall back to Sysmon proxies (remote thread, process access, image load) and state the limitation |
| Python collector drops events under load | Skews results | Measure drops; isolate collector from analysis; move hot path to C#/C++ only if measured necessary |
| Ground-truth labeling is biased toward the strategy design | Invalid comparison | Define labels from scenario scripts before implementing strategies; freeze them |
| Small scenario set overfits | Results do not generalize | Multiple scenario families, randomized noise, say plainly that results are lab-scoped |
| Scope creep | Never finishes | Milestone exit criteria in `IMPLEMENTATION_PLAN.md`; cut list defined there |
