# IMPLEMENTATION PLAN — V-MBOX

Software-only, Windows, Python-first. Milestones are ordered by dependency; each has exit criteria that must be demonstrably true before moving on. Effort sizes (S ≈ a few days, M ≈ 1–2 weeks, L ≈ 2–3 weeks of part-time work) are rough guesses, not commitments, so re-estimate after M1.

## Dependency order

```
M0 → M1 → M2 → M3 → M4
              ↓
              M5 (scenarios + labels, frozen) → M6 (strategies) → M7 → M8 → M9 → M10
```
M5 can start in parallel with M3–M4 but labels must freeze before M6 tuning.

---

## M0 — Foundation (S)

**Tasks**
- Repo skeleton per `README.md`, `pyproject.toml`, `ruff`, `mypy`, `pytest`, CI for unit tests
- `canonical_json()` and `Event` / manifest dataclasses from `SCHEMA.md`
- Schema validation tests

**Exit criteria**
- `pytest` green in CI
- Same event → byte-identical canonical output across runs and machines
- `SCHEMA.md` and code agree (a test loads the examples from the doc)

---

## M1 — Telemetry validation spike (M) — *decides the memory-event story*

**Tasks**
- Windows VM + Sysmon (minimal config) + snapshot workflow
- ETW consumer prototype for Kernel-Process and Kernel-Network
- Sysmon event-log subscription for IDs 1, 3, 5, 7, 8, 10
- Run a noisy benign workload and a scripted injection-like test; record event rates and **drop counters**
- Investigate any usable memory-protection-change source; decide in/out for `MEM_PROTECT_CHANGE`
- Measure Python collector CPU and loss at observed rates

**Exit criteria**
- Written 1-page findings: which events are reliably observable, at what rate, with what loss
- Decision recorded in `DESIGN.md` §3.1: memory category = which events exactly
- Go/no-go on Python collector vs porting the hot path

**Risk:** if memory proxies are too thin to form a meaningful trigger, rewrite the context-aware rules around process/network lineage and say so in the docs.

---

## M2 — Pipeline: collect → normalize → raw trace → replay (M)

**Development status (2026-10-20):** The synthetic live callback and replay
produce byte-identical normalized events from the same raw trace. Windows VM
live/replay identity and forced queue-overflow behavior still need a new VM run.

**Tasks**
- `Source` interface, `EtwSource`, `SysmonSource`, `ReplaySource`
- Normalizer assigning `seq`, `session_id`, `boot_id`, handling capture status
- Collector queues, `CAPTURE_GAP` emission, start/stop events
- `--tee-raw` raw trace writer (full unfiltered archive, hashed)
- Replay produces identical normalized output from a raw trace

**Exit criteria**
- Live capture and replay of the same trace give byte-identical normalized streams (excluding live timestamps)
- Forced queue overflow produces a `CAPTURE_GAP` with count
- Raw traces from at least two workloads archived

---

## M3 — Store and integrity (L)

**Tasks**
- Journal: CRC frames, ring behavior, torn-write handling
- Segment sealing: temp → flush → rename → chain
- Hash chain, genesis from manifest, `verify`
- Budget accounting (journal + segments + tombstones) and eviction to tombstones
- Property tests: round-trip, tamper detection per region, torn-write recovery

**Exit criteria**
- Every injected corruption (header, body, footer, tombstone) is detected by `verify` with the right classification
- Kill-during-seal never yields a segment accepted as complete when it isn't
- Chain still verifies across tombstones
- Budget never exceeded in a long soak run

---

## M4 — Anchor and checkpoints (M)

**Development status (2026-10-20):** The offline ledger and signed receipt
verification are implemented. A bounded HMAC-authenticated TCP transport,
write-once key setup, host checkpoint retry, and a Sysmon-only live recorder
pass loopback/synthetic tests. Second-VM transport, outage recovery, and
power-loss durability are **unverified until run on the Windows VMs**; use
`LIVE_RUNBOOK.md` to validate them. The private key must stay on the anchor VM.

**Tasks**
- Anchor service with Ed25519 key, chained signed receipts
- Checkpoint client with outage handling (`chained` vs `anchored`)
- Verification against anchor public key only
- Second-VM deployment

**Exit criteria**
- Rewriting an anchored segment (and recomputing the host chain) is detected via receipt mismatch
- Deleting the latest unanchored segments is reported as missing receipts / truncation
- Recorder keeps running and logs the outage when the anchor is down
- Test and docs state plainly what this does *not* prove

---

## M5 — Scenarios, labels, eval harness (L)

**Tasks**
- Scenario runner emitting `labels.json` (matches `SCHEMA.md` §8)
- At least 3 scenario families, e.g. stager → remote-thread injection → outbound connection; child-process chain → connection; benign-lookalike (software installer / updater that also spawns and connects)
- Benign noise workloads (browsing, office, build) with randomized parameters per seed
- Label matching rules, manual spot-check of matched events
- Eval harness: replay trace × strategy × budget × seed → per-run `result.json`
- Metrics implemented and unit-tested on synthetic cases with known answers
- **Freeze labels** (hash recorded)

**Exit criteria**
- Harness runs end to end with dummy strategy and an unbounded baseline (coverage ≈ collection coverage)
- Metric functions pass hand-computed test cases
- Labels frozen and hashed; held-out scenario set designated

**Status (2026-10-20): complete for M5.** The strategy-facing harness is exercised end to end by a synthetic dummy and the unbounded baseline. Metric helpers pass hand-computed synthetic cases. A real `query_connect` trace was captured, manually reviewed, frozen, replayed, and locally verified; its limits are recorded beside its result. `child_chain` is designated held-out and has not been used for tuning. Further strategy implementations and comparisons belong to M6; more VM runs and statistical aggregation belong to M8.

---

## M6 — Selection strategies (L)

**Development status (2026-10-20): in progress.** The first offline selector slice implements
FIFO, fixed allow-list, static priority, and context promotion under frozen rule tag
`m6-general-v2`. The v2 tag adds target-PID activity and direct child inheritance to v1.
Synthetic harness tests exercise four equal total budgets. The M6 batch path seals multiple
segments, verifies the chain across tombstones, and uses priority/context scores for eviction.
The Windows VM replay completed at the planned budgets according to operator output, with
local chain verification for each run. The raw trace and result files remain on the VM;
this repository has not independently reproduced them. Because the journal appears large
enough to retain the whole trace, the reported coverage cannot distinguish selection
quality. A sealed-versus-journal retention audit is now documented in `M6_RUNBOOK.md`.
M6 exit review remains pending that audit and the recorded run artifacts.

**Tasks**
- Strategy interface; baselines (unbounded, FIFO ring)
- Fixed-policy, priority-based, context-aware (windowed promotion, lineage inheritance)
- Trigger rules written from general patterns, versioned, frozen
- Budget-aware eviction using priorities and context protection
- Per-segment `selection_stats`

**Exit criteria**
- All strategies run through the harness at ≥4 budgets
- Each strategy respects the same total budget (verified by test)
- Strategies cannot access labels (enforced by interface + test)
- Rule set version tagged in git

---

## M7 — Recovery, reconstruction, report (L)

Recovery, timeline, and deterministic JSON/HTML reports are implemented for
existing evidence. Forced-kill and power-off tests are **unverified until run on
Windows VM**. Relation precision/recall remains **not measured** because frozen
labels currently identify events, not a complete truth set of relations; adding
one requires an explicit SCHEMA.md change before a metric can be reported.

**Tasks**
- `recover`: sessions, journal validation, segment/chain/receipt checks, gap classification
- Reconstruction: timeline by `seq`, derived relations (PID-reuse safe), inferred relations with confidence caps
- `timeline`, `report` (JSON + single-file HTML), exit codes per `APPFLOW.md`
- Reconstruction accuracy metrics vs labels

**Exit criteria**
- After kill/power-off tests, `recover` reports surviving data and accurately flags the torn tail and gaps
- Report always shows integrity levels, gaps, tombstones, limitations
- No report text claims intent, attribution, or exfiltration (checked by a test on templates)

---

## M8 — Experiments (L)

**Development status (2026-10-20): offline aggregation implemented, experiment
runs pending.** A write-once equal-budget matrix runner is available for each
new independent frozen trace. Per-run v2 results record tuning/held-out role. The v1 reader
requires an explicit hashed role map and never rewrites old files. A canonical
attempt manifest and derived `results.json` preserve failed-run accounting,
paired trace comparisons, CI settings, and input hashes. The table renderer
accepts only validated aggregates. The existing M6 data contain one independent
trace, so CIs and comparison conclusions remain **not measured/inconclusive**.
Live overhead, latency, crash, and held-out matrix work still require VM runs.

**Tasks**
- Run full matrix: scenarios × strategies × budgets × seeds (enough seeds for stable CIs)
- Live runs for overhead and persistence latency (collector on/off, same workload)
- Crash-injection runs for crash-recovery rate (randomized kill points, VM power-off)
- Held-out scenario evaluation
- Plots and tables with CIs; archive traces, configs, labels, results

**Exit criteria**
- All headline numbers reproducible from archived inputs with one command
- Results reported with run counts, CIs, and collection coverage next to evidence coverage
- Any strategy-vs-baseline claim backed by a difference larger than variance, otherwise stated as inconclusive

---

## M9 — Trust and resilience tests (M)

**Development status (2026-10-20): synthetic local probes implemented.**
Pre-seal collector changes, full copied-chain rewrites, and missing host
receipts are tested in `tests/test_m9_resilience.py`; their limits are recorded
in `M9_LOCAL_PROBES.md`. Windows VM and second-VM anchor behavior are unverified.

**Tasks**
- Compromised-collector simulation: fabricated events, suppressed events, altered timestamps
- Host-side evidence tampering (modify, delete, truncate, full chain rewrite) with and without anchor
- Anchor outage scenarios
- Document observed behavior vs claimed guarantees

**Exit criteria**
- Table of attack × detected / not detected / detected only in anchored range, from actual tests
- Threat model in `DESIGN.md` §9 updated to match reality

---

## M10 — Documentation and writeup (M)

**Development status (2026-10-20):** architecture, method, related-work
distinctions, reproducibility status, and limitations are drafted in
`M10_WRITEUP.md` and `M10_STATUS.md`. A final results discussion is pending
independent held-out traces and live/tamper validation; no missing metric is
filled from a synthetic probe.

**Tasks**
- Final threat model, architecture, related work (memory forensics, Windows telemetry, tamper-evident logging, forward-secure logging literature), methodology, results, limitations
- README quick start with real commands and real results
- Reproducibility package: trace hashes, configs, scripts

**Exit criteria**
- A fresh clone plus archived traces regenerates the reported tables
- Limitations section covers collection gaps, proxy-only memory events, lab scope, compromised-collector limit

---

## Cut list (if time runs short, in this order)

1. HTML report polish (keep JSON + Markdown)
2. `MEM_PROTECT_CHANGE` (already optional)
3. Priority-based strategy refinements (keep a simple version as the middle baseline)
4. Live power-off crash tests (keep process-kill tests, say so)
5. Third scenario family
6. Anchor transport hardening (keep local named-pipe/TCP with pre-shared credential)

**Do not cut:** frozen labels, equal-budget comparison, baselines, tamper tests, limitations reporting.

## Top risks and responses

| Risk | Response |
|---|---|
| Memory telemetry too thin (M1) | Rebuild triggers around process/network lineage, state the limitation |
| Python collector drops events | Measure first; port only the collector to C#/C++ behind `Source` |
| Context-aware shows no benefit | Report it; analyze which scenarios/budgets differ |
| Scenarios too artificial | Include benign lookalikes and noise variation; label results lab-scoped |
| Scope creep | Exit criteria per milestone and the cut list above |

## Definition of done

- End-to-end recording, crash, recovery, verification, report works on the lab VM
- Three strategies and two baselines evaluated at equal budgets with honest statistics
- Tamper and compromised-collector behavior documented from tests
- Every claim in the docs traces to a result or is marked "planned" or "not measured"
