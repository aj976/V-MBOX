# M7 recovery and report check (Windows VM)

These commands inspect existing M6 offline evaluation evidence. They do not
create forensic evidence, and they do not establish crash recovery performance.
Use new output directories; report files are write-once.

```powershell
cd C:\Users\aatmi\OneDrive\Desktop\vmbox
git pull origin main
python -m pytest .\tests\test_recovery.py .\tests\test_relations.py .\tests\test_report.py .\tests\test_cli_recovery.py -q

python -m vmbox.cli recover --evidence .\runs\family1_unbounded_m6
$recoverExit = $LASTEXITCODE
python -m vmbox.cli timeline --evidence .\runs\family1_unbounded_m6 --pid 4892
$timelineExit = $LASTEXITCODE
python -m vmbox.cli report --evidence .\runs\family1_unbounded_m6 --out .\runs\family1_m7_report_1
$reportExit = $LASTEXITCODE
Get-Content .\runs\family1_m7_report_1\report.json -Raw
Start-Process .\runs\family1_m7_report_1\report.html
"recover=$recoverExit timeline=$timelineExit report=$reportExit"
```

`--pid` is only an example filter; omit it to see the full timeline. The report
must say **offline evaluation session, not forensic evidence**. Its JSON
`content_hash` must match the visible HTML hash. Verify output and exit code are
copied from the `verify` command, while the separate recovery status can mark
gaps and tombstones as incomplete. Exit codes are 0 for okay, 2 for failed
integrity, and 3 for incomplete evidence. Unknown ranges print `unknown`.

Inspect a budgeted run with tombstones separately:

```powershell
python -m vmbox.cli recover --evidence .\runs\m6_context_aware_9mib
$budgetedExit = $LASTEXITCODE
python -m vmbox.cli report --evidence .\runs\m6_context_aware_9mib --out .\runs\family1_m7_budgeted_report_1
"budgeted recover=$budgetedExit report=$LASTEXITCODE"
```

The budgeted run should list tombstones and exit 3; journal-only events must
never be labeled chained or anchored. If an output directory already exists,
choose a new name instead of overwriting it. Keep the original evidence and
frozen labels unchanged.

Forced process termination and VM power-off recovery are **unverified until run
on Windows VM with a live recorder**. The current `record` CLI is not implemented,
so these tests cannot yet be performed. Do not fill crash-recovery or latency
metrics from this offline check. Relation precision/recall is also **not
measured**: the frozen label format has no complete relation truth set.
