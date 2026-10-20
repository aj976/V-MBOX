# M5 scenario labels and review — current implementation

The VM-only scenario runner, Sysmon-only raw capture script, and their live matching are **unverified until run on a Windows VM with a real captured trace**. The general `vmbox record` command is still planned. Do not treat a scenario run by itself as an evaluated result. M5 metric functions are unit-tested on synthetic cases; no strategy comparison or VM M5 metric has been measured.

The scenario runner supports three benign simulation families: `child_chain`, `query_connect`, and `benign_lookalike`. `query_connect` only opens a query-limited process handle and makes a loopback connection; it does not inject code or modify another process. Each run starts a uniquely named marker process with a nonce in its image name. The runner writes canonical `labels.draft.json` before executing the workload. Windows are inclusive offsets from the marker event, based on a five-second intended workload plus three seconds of collection tolerance; they are not adjusted after strategy results are seen. Seeded benign noise runs alongside the family. The marker launcher and scenario/event pairing need a VM capture before they can be claimed to work.

Before strategy tuning, `child_chain` is designated the held-out scenario family. Use `query_connect` for development checks and `benign_lookalike` to inspect false associations. This small split is a lab scope limit, not evidence of generalization.

To obtain a trace on the isolated VM, install the same `docs/sysmon.xml` config as in the M1 runbook immediately before capture. Create a fresh `runs` directory and use two elevated PowerShell terminals in the repo root. Start terminal A first:

```powershell
New-Item -ItemType Directory -Path .\runs -ErrorAction SilentlyContinue
sysmon64 -c .\docs\sysmon.xml
python .\scripts\m5_capture.py --duration 30 --out .\runs\family1_trace.jsonl --sysmon-config .\docs\sysmon.xml
```

When A prints `capture_ready`, run terminal B:

```powershell
python .\scenarios\run_m5.py --family query_connect --seed 1 --out .\runs\family1_labels
```

Keep the raw trace local: it can include hostnames, usernames, paths, and IP addresses even though command lines are hashed by default. Do not commit or share it without sanitization. If A reports a queue overflow, the trace contains a `CAPTURE_GAP`; do not treat it as complete. Sysmon upstream loss remains unmeasured. A nonzero scenario exit or absent/duplicated marker invalidates the run.

After the trace and its `.sha256` sidecar exist, use these commands from the repo root:

```powershell
python .\scripts\m5_labels.py prepare --trace .\runs\family1_trace.jsonl --draft .\runs\family1_labels\labels.draft.json --review .\runs\family1_labels\match_review.json
```

The command fails if the nonce marker is absent or duplicated. It writes `match_review.json` with every ambiguous step and its candidate event IDs. Inspect those candidates against the trace, then record each decision with who/when:

```powershell
python .\scripts\m5_labels.py resolve --review .\runs\family1_labels\match_review.json --step-id s1 --event-id <candidate-event-id> --reviewer <your-name>
python .\scripts\m5_labels.py freeze --trace .\runs\family1_trace.jsonl --draft .\runs\family1_labels\labels.draft.json --review .\runs\family1_labels\match_review.json --out .\runs\family1_labels\labels.json
```

`freeze` replays the trace again, requires all ambiguous matches to be resolved, and writes `labels.json` once. The printed SHA-256 covers the canonical labels including reviewer identity and timestamp. A changed window or review after freeze requires a new labels version. Zero-candidate attack steps are collection misses; a missing or ambiguous marker makes the run unlabeled. The manually reviewed label set and any future result must remain tied to the exact trace hash and run provenance.
