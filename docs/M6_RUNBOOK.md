# M6 offline strategy replay (Windows VM)

Run this only after pulling the M6 commits. Keep the original trace and frozen labels
unchanged. These are offline evaluation sessions, not forensic evidence. The output
directories are write-once; use new names for retries. Real M6 comparisons are **not
measured** until these commands finish on the VM.

```powershell
cd C:\Users\aatmi\OneDrive\Desktop\vmbox
git pull origin main
$sysmonVersion = (Get-Item (Get-Command sysmon64.exe).Source).VersionInfo.ProductVersion
python -m pip freeze --all | Out-File -Encoding utf8 .\runs\requirements-lock-m6.txt
python .\scripts\m5_eval.py --trace .\runs\family1_trace.jsonl --labels .\runs\family1_labels\labels.json --out .\runs\family1_unbounded_m6 --journal-bytes 8388608 --lockfile .\runs\requirements-lock-m6.txt --sysmon-version $sysmonVersion
```

The new unbounded run supplies the measured full-size denominator using the current
serialization. Run every strategy at the **same four total budgets**. Each budget
includes the 8 MiB journal, sealed segments, and tombstones; receipts are excluded.

```powershell
$trace = '.\runs\family1_trace.jsonl'
$labels = '.\runs\family1_labels\labels.json'
$full = '.\runs\family1_unbounded_m6\result.json'
$lock = '.\runs\requirements-lock-m6.txt'
foreach ($strategy in @('fifo_ring', 'fixed', 'priority', 'context_aware')) {
    foreach ($budgetMiB in @(9, 10, 11, 12)) {
        $out = ".\runs\m6_${strategy}_${budgetMiB}mib"
        python .\scripts\m6_eval.py --trace $trace --labels $labels --full-result $full --out $out --strategy $strategy --budget-bytes ($budgetMiB * 1048576) --journal-bytes 8388608 --segment-events 128 --lockfile $lock --sysmon-version $sysmonVersion
        if ($LASTEXITCODE -ne 0) { throw "M6 replay failed: $strategy at $budgetMiB MiB" }
        python -m vmbox.cli verify --evidence $out
        if ($LASTEXITCODE -ne 0) { throw "M6 verify failed: $out" }
    }
}
```

Retain all `result.json` files and the command output. `event_loss_rate` measures
unexplained loss relative to events in the verified raw trace; it cannot measure
Sysmon upstream loss. Integrity is `chained` at best for these offline sessions.
If a run fails, keep its incomplete output directory and report the exact error;
do not reuse or delete it during investigation.

### Retention audit for completed runs

`evidence_coverage` includes events recovered from the unverified journal. If the
journal can hold the entire trace, that metric cannot distinguish the selectors.
Run this read-only audit against the existing output directories to separate
hash-chained sealed retention from journal-only retention. It changes no evidence
files or result metrics.

```powershell
git pull origin main
python .\scripts\m6_audit.py --trace .\runs\family1_trace.jsonl --labels .\runs\family1_labels\labels.json --run-root .\runs
```

Share the audit output for review. `sealed_coverage` is a diagnostic computed from
verified sealed segments; it is not a field in the version-1 evaluation result.
