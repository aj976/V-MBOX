# RULES — V-MBOX

Rules for anyone (human or AI assistant) changing this repo. If a rule blocks the work, change the rule in a PR, don't quietly break it.

## 1. Honesty rules (highest priority)

1. **No fabricated or placeholder metrics.** Every number in docs, reports, or the README comes from a recorded run and links to its `results.json`. Until a run exists, write "not measured".
   Unmeasured metrics are `null` in data and "not measured" in prose, never `0` or an estimate.
2. **Don't claim detection.** V-MBOX preserves and reconstructs evidence. No output, comment, or doc says an event "is malicious", "proves", or "shows exfiltration".
3. **Observed ≠ derived ≠ inferred.** Keep the `provenance` field truthful. Temporal proximity is `inferred`, never `high` confidence.
4. **Integrity ≠ authenticity ≠ completeness.** Never describe a verified chain as "trusted evidence". Say what was verified.
5. **Report limits next to results.** Collection coverage, gaps, tombstones, and lab-only scope appear wherever results do.
6. **Null results get published.** If context-aware doesn't beat baselines, say so.
7. **Memory telemetry is proxies** unless a validated source exists. Name it accurately.

## 2. Evaluation integrity

1. Ground-truth labels are written from scenario scripts and **frozen before** strategy tuning. Changing labels after seeing results = new experiment version.
2. Context-aware trigger rules are frozen per experiment version; edits create a new version.
3. All strategies get the same raw trace, the same total budget (journal + segments + tombstones), and the same seeds.
4. Include baselines (unbounded, FIFO ring) in every comparison.
5. Every result records: trace hash, label hash, config hash, git commit, seed, tool versions.
6. Report mean ± 95% CI and run count. Don't claim effects below the variance.
7. Don't tune on the scenarios you report on. Keep a held-out scenario set.

## 3. Code rules

1. **Canonical serialization only** for anything hashed. One function (`canonical_json`) owns it; no ad-hoc `json.dumps` for persisted evidence.
2. `seq` is assigned in the normalizer before selection. Nothing downstream renumbers events.
3. Evidence files are write-once. Sealing is: write temp, flush to disk, atomic rename, extend chain, checkpoint. Never overwrite a sealed segment.
4. Never treat incomplete data as complete: a bad CRC, missing footer, or hash mismatch is a reported gap or tamper result, not a silent skip.
5. Components fail loud: errors become `CAPTURE_GAP` or explicit exit codes, not swallowed exceptions.
6. Strategies implement the same interface and can't read ground-truth labels.
7. Secrets: the anchor private key never lives in the monitored VM or in the repo.
8. `integrity/` and `store/` are `mypy --strict` and need property tests (round-trip, tamper detection, torn-write handling).
9. No kernel drivers, no real malware, no network egress from scenarios beyond the isolated lab.
10. Keep modules small and single-purpose per the layout in `README.md`; no cross-layer imports (e.g. `select/` must not import `store/`).

## 4. Testing rules

- Every module ships with unit tests. Parsers have fixtures from real captured events (sanitized).
- Tamper tests: flip a byte in each region (header, body, footer, tombstone, receipt) and assert detection.
- Crash tests: forced collector kill and VM power-off at randomized points; assert committed records recover and the torn tail is flagged.
- Replay determinism test: same trace + seed + config → byte-identical outputs.
- CI runs unit and property tests; VM-dependent tests are marked and run manually with results logged.

## 5. Documentation rules

1. `SCHEMA.md` is the source of truth for formats. Code changes to formats update it in the same commit and bump `schema_version` after the first real artifact is persisted. Before that point, version 1 may be corrected in place.
2. Design decisions go in the `DESIGN.md` decisions log with the alternative considered.
3. Docs describe what exists. Planned items are marked "planned".

## 6. Safety and scope rules

- Attack-like scenarios run only in the isolated VM, with snapshots.
- No collection of data from machines other than your own lab VMs.
- Command lines may contain secrets: store `cmdline_hash` by default; raw `cmdline` is opt-in and off in committed traces.
- Sanitize any trace before sharing or committing (hostnames, usernames, IPs).

## 7. Working style (for AI assistants)

- Be concise. Match the user's casual, direct style, and skip filler.
- Infer intent from existing docs and replicate established formats instead of asking.
- Flag problems with the plan, honestly and briefly, rather than going along silently.
- If a requested change conflicts with these rules, say which rule and propose the compliant alternative.
