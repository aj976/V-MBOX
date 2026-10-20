# M5 scenario labels and review — current implementation

The VM-only scenario runner and live matching are **unverified until run on a Windows VM with a real captured trace**. The current repository does not yet have a live `vmbox record` command that writes an M5 raw trace, so do not treat a scenario run by itself as an evaluated result. M5 metric functions are unit-tested on synthetic cases; no strategy comparison or VM M5 metric has been measured.

The scenario runner supports three benign simulation families: `child_chain`, `query_connect`, and `benign_lookalike`. `query_connect` only opens a query-limited process handle and makes a loopback connection; it does not inject code or modify another process. Each run starts a uniquely named marker process with a nonce in its image name. The runner writes canonical `labels.draft.json` before executing the workload. Windows are inclusive offsets from the marker event, based on a five-second intended workload plus three seconds of collection tolerance; they are not adjusted after strategy results are seen. Seeded benign noise runs alongside the family. The marker launcher and scenario/event pairing need a VM capture before they can be claimed to work.

After a verified raw trace is available, use these commands from the repo root (replace paths with your run's actual files):

```powershell
python .\scripts\m5_labels.py prepare --trace .\runs\trace.jsonl --draft .\runs\labels.draft.json --review .\runs\match_review.json
```

The command fails if the nonce marker is absent or duplicated. It writes `match_review.json` with every ambiguous step and its candidate event IDs. Inspect those candidates against the trace, then record each decision with who/when:

```powershell
python .\scripts\m5_labels.py resolve --review .\runs\match_review.json --step-id s1 --event-id <candidate-event-id> --reviewer <your-name>
python .\scripts\m5_labels.py freeze --trace .\runs\trace.jsonl --draft .\runs\labels.draft.json --review .\runs\match_review.json --out .\runs\labels.json
```

`freeze` replays the trace again, requires all ambiguous matches to be resolved, and writes `labels.json` once. The printed SHA-256 covers the canonical labels including reviewer identity and timestamp. A changed window or review after freeze requires a new labels version. Zero-candidate attack steps are collection misses; a missing or ambiguous marker makes the run unlabeled. The manually reviewed label set and any future result must remain tied to the exact trace hash and run provenance.
