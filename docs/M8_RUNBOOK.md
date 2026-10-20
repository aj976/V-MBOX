# M8 aggregate preparation (Windows VM)

The existing M6 run is **one independent trace**. Its 17 result files can test
aggregation, but they cannot supply a 95% CI; the default minimum is 10
independent traces per group. Deterministic strategy replays of that one trace
do not increase `n`. Existing v1 files remain unchanged.

After pulling these commits, select the exact completed run directories. The
role is an explicit choice: `query_connect` seed 1 was used during development,
so mark it `tuning`.

```powershell
cd C:\Users\aatmi\OneDrive\Desktop\vmbox
git pull origin main
$runDirs = @((Get-Item .\runs\family1_unbounded_m6)) + @(
    Get-ChildItem .\runs -Directory |
    Where-Object Name -Match '^m6_(fifo_ring|fixed|priority|context_aware)_(9|10|11|12)mib$'
)
$runPaths = @($runDirs | ForEach-Object FullName)
if ($runPaths.Count -ne 17) { throw "Expected 17 selected runs, found $($runPaths.Count)" }

python .\scripts\m8_prepare.py --attempts-out .\runs\m8_attempts_1.json --roles-out .\runs\m8_roles_1.json --set-role tuning @runPaths
python .\scripts\m8_aggregate.py --attempts .\runs\m8_attempts_1.json --legacy-role-map .\runs\m8_roles_1.json --out .\runs\m8_results_1.json --table-out .\runs\m8_tables_1.md
Get-Content .\runs\m8_tables_1.md
```

The preparation step writes canonical `run_id → role` mappings for v1 files.
The aggregate records their exact hash, each input result hash, all completed
run IDs, and any explicitly listed failed runs. To add a known failure during
inventory, pass `--failed 'run-id=reason'`; never omit a failed attempted run.
Both outputs are write-once, so use new names on retry. Only the validated
`results.json` produces the tables. Collection coverage appears next to
evidence coverage; unavailable metrics show `not measured` and every comparison
should be `inconclusive` with one trace.

For future independent traces, repeat capture and frozen-label preparation with
different noise inputs/seeds, then replay every strategy and budget on **each**
trace. New `m5_eval.py` and `m6_eval.py` invocations require `--set-role tuning`
or `--set-role held_out` and write v2 results. Do not relabel the existing
development trace as held-out. A held-out aggregate is prepared separately,
using an explicit `held_out` role, so tuning and held-out traces are not pooled.
Live overhead, persistence latency, crash-recovery rate, and any CI based on
fewer than the configured independent runs remain **not measured**.

For each **new independent trace** with frozen labels, `m8_matrix.py` runs the
unbounded reference first, then all four strategies at the same supplied
budgets. It creates a write-once output folder, one log per attempted replay,
and `attempts.json` with explicit failed-run records. A failed reference stops
the matrix after recording that failed attempt; do not reuse its output folder.
A failed budgeted
run is retained in the attempt inventory and prevents a complete paired
aggregate until it is investigated and rerun as a new attempt.

```powershell
$sysmonVersion = (Get-Item (Get-Command sysmon64.exe).Source).VersionInfo.ProductVersion
python .\scripts\m8_matrix.py --trace .\runs\new_trace.jsonl --labels .\runs\new_labels\labels.json --out .\runs\matrix_new_trace_1 --lockfile .\runs\requirements-lock-m6.txt --sysmon-version $sysmonVersion --set-role held_out --journal-bytes 8388608 --segment-events 128 --budget-bytes 9437184 10485760 11534336 12582912
```

The paths above are **command shape**, not existing files: substitute a new
trace, its own frozen labels, an appropriate tuning/held-out role, and fresh
output directory. For each scenario family and role, collect enough distinct
traces for the configured minimum (default 10) before interpreting CIs.
Different deterministic replays of one trace never increase independent `n`.
