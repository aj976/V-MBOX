# SCHEMA — V-MBOX

All persisted structures use **canonical JSON** (UTF-8, keys sorted, no insignificant whitespace, integers as integers, timestamps as integer nanoseconds since Unix epoch UTC) so hashes are reproducible. Field names are `snake_case`.

Schema version: `1`. Every segment and manifest records it.

## 1. Event record

```json
{
  "schema_version": 1,
  "event_id": "01J...",
  "session_id": "uuid",
  "boot_id": "string",
  "seq": 18422,
  "ts_ns": 1760000000123456789,
  "ts_source": "etw_qpc",
  "event_type": "NET_CONNECT",
  "category": "network",
  "pid": 4312,
  "ppid": 1180,
  "process": { "image": "C:\\...\\x.exe", "cmdline_hash": "sha256:...", "cmdline": null },
  "data": { },
  "provenance": "observed",
  "capture": { "source": "etw_kernel_network", "status": "ok", "collector_version": "0.1.0" },
  "priority": null,
  "tags": []
}
```

### Field rules

| Field | Rule |
|---|---|
| `seq` | Strictly increasing per session, assigned by the normalizer *before* selection. Gaps in persisted `seq` are therefore meaningful: either dropped by selection (recorded in tombstone/selection stats) or lost |
| `boot_id` | Derived from system boot time; changes after reboot |
| `ts_source` | `etw_qpc`, `sysmon_utc`, `wallclock`, `replay`. Timestamps are never assumed trustworthy (see `DESIGN.md` threat model) |
| `provenance` | `observed` (directly reported by a source), `derived` (computed from observed events, e.g. lineage), `inferred` (heuristic). Only `observed` is allowed on raw events; derived/inferred appear in reconstruction output |
| `process.cmdline` | Nullable. Stored only if configured; `cmdline_hash` always stored |
| `priority` | Set by the selector (`null` before). Numeric, strategy-specific |
| `capture.status` | `ok`, `partial` (some fields unavailable), `source_error`, `dropped_upstream` |

### Event types

| `event_type` | Category | Source | `data` fields |
|---|---|---|---|
| `PROC_START` | process | ETW Kernel-Process / Sysmon 1 | `image`, `parent_image`, `user`, `integrity_level?` |
| `PROC_EXIT` | process | ETW Kernel-Process / Sysmon 5 | `exit_code?` |
| `NET_CONNECT` | network | ETW Kernel-Network / Sysmon 3 | `proto`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `direction` |
| `NET_CLOSE` | network | ETW Kernel-Network | `proto`, `src_*`, `dst_*` |
| `MEM_REMOTE_THREAD` | memory | Sysmon 8 | `source_pid`, `target_pid`, `start_address`, `start_module?` |
| `MEM_PROCESS_ACCESS` | memory | Sysmon 10 | `source_pid`, `target_pid`, `granted_access` |
| `MEM_IMAGE_LOAD` | memory | Sysmon 7 | `image_loaded`, `signed?`, `hashes?` |
| `MEM_PROTECT_CHANGE` | memory | *experimental*, only if a source is validated in M1 | `address`, `size`, `old_prot`, `new_prot` |
| `CAPTURE_GAP` | meta | collector | `reason`, `source`, `approx_missed?` |
| `COLLECTOR_START` / `COLLECTOR_STOP` | meta | collector | `config_hash`, `sources` |

Memory events are **proxies** for memory-related activity. Reports must call them what they are.

## 2. Session manifest

Written at session start, hashed into the chain genesis.

```json
{
  "schema_version": 1,
  "session_id": "uuid",
  "boot_id": "string",
  "host": "hostname",
  "start_ts_ns": 0,
  "collector_version": "0.1.0",
  "config_hash": "sha256:...",
  "strategy": "context_aware",
  "budget_bytes": 67108864,
  "journal_bytes": 8388608,
  "anchor": { "endpoint": "host:port", "pubkey_fingerprint": "sha256:..." }
}
```

## 3. Journal (unsealed)

Append-only file `journal.bin`, a ring of fixed capacity (`journal_bytes`).

Frame: `[u32 length][u32 crc32][payload = canonical event JSON]`

- CRC detects torn writes. A frame with bad CRC or short length ends valid data.
- Journal contents are **unverified**: no chain, no anchor. Reports must label anything recovered only from the journal as such.

## 4. Sealed segment

File `seg_<index:08d>.vseg`.

```
HEADER   (canonical JSON, one line): {
  "schema_version":1, "session_id":"...", "index":12,
  "seq_start":..., "seq_end":..., "record_count":..., "ts_start_ns":..., "ts_end_ns":...,
  "prev_hash":"sha256:...", "strategy":"...", "selection_stats":{...}
}
BODY     records: [u32 length][payload]...   (canonical event JSON, ascending seq)
FOOTER   (canonical JSON, one line): { "segment_hash":"sha256:...", "body_sha256":"sha256:..." }
```

Chain: `H(i) = SHA-256( H(i-1) || S(i) )` where `S(i)` = header bytes ‖ body bytes (exactly as stored, canonical). `H(0)` = SHA-256 of the canonical session manifest.

`selection_stats` (per segment): `seen`, `kept`, `dropped_by_policy`, `by_type` counts, `promoted_by_context`. This lets reports separate "dropped on purpose" from "lost".

## 5. Tombstone

When the budget forces eviction, a sealed segment body is deleted and replaced by `seg_<index>.tomb`:

```json
{
  "index": 12, "seq_start": 0, "seq_end": 0, "record_count": 0,
  "ts_start_ns": 0, "ts_end_ns": 0,
  "prev_hash": "sha256:...", "segment_hash": "sha256:...",
  "evicted_reason": "budget", "evicted_ts_ns": 0
}
```

The chain still verifies across tombstones because `segment_hash` is retained. The tombstoned content itself is no longer verifiable or recoverable, and the report says so.

## 6. Checkpoint and anchor receipt

Checkpoint (host → anchor):

```json
{ "session_id": "uuid", "segment_index": 12, "segment_hash": "sha256:...", "seq_end": 0, "host_ts_ns": 0 }
```

Receipt (anchor → host, stored by both):

```json
{
  "checkpoint": { },
  "anchor_ts_ns": 0,
  "anchor_seq": 57,
  "prev_receipt_hash": "sha256:...",
  "signature": "ed25519:..."
}
```

The anchor chains receipts to each other and signs with its own key, which the host never holds. Verification uses only the anchor public key.

## 7. Reconstruction output

```json
{
  "timeline": [
    { "ref": "event_id", "ts_ns": 0, "integrity": "anchored|chained|journal_only|unverified|tampered" }
  ],
  "relations": [
    {
      "relation_id": "r1",
      "type": "parent_of|spawned_then_connected|remote_thread_into|temporal_proximity",
      "from": "event_id", "to": "event_id",
      "provenance": "derived|inferred",
      "basis": "ppid match | same pid within 2.0s | ...",
      "confidence": "high|medium|low"
    }
  ],
  "gaps": [ { "kind": "seq_gap|capture_gap|interruption|tombstone|incomplete_write", "seq_range": [0,0], "ts_range_ns": [0,0] } ],
  "limitations": [ "string" ]
}
```

`temporal_proximity` is always `inferred` and never `high`.

## 8. Ground-truth label (evaluation only)

`scenarios/<name>/labels.json`, written by the scenario runner, frozen before strategy evaluation:

```json
{
  "scenario_id": "inject_then_connect",
  "run_id": "uuid",
  "seed": 1337,
  "steps": [
    {
      "step_id": "s1",
      "description": "launch stager",
      "match": { "event_type": "PROC_START", "image_regex": "...stager.exe", "ts_window_ns": [0, 0] },
      "relevance": "attack"
    }
  ],
  "benign_workload": "browse_office_build_v1"
}
```

Matching of recorded events to steps is rule-based, then manually spot-checked. Unmatched attack steps count against *collection*, separately from *selection* (see metrics).

## 9. Evaluation result

Template, not a measurement. `null` metrics mean "not measured". A result is invalid if any provenance field is missing. `tool_versions.etw_pywintrace` is required when ETW/pywintrace was used and otherwise is `null`.

```json
{
  "run_id": "uuid", "scenario_id": "example", "seed": 0,
  "strategy": "context_aware", "budget_bytes": 0, "budget_fraction_of_full": null,
  "trace_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "label_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "config_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "git_commit": "0000000000000000000000000000000000000000",
  "git_dirty": false,
  "strategy_rules_version": "not measured",
  "tool_versions": {
    "python": "not measured", "vmbox": "not measured",
    "lockfile_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "windows_build": "not measured", "sysmon_version": "not measured",
    "etw_pywintrace": null
  },
  "metrics": {
    "evidence_coverage": null,
    "collection_coverage": null,
    "reconstruction_accuracy": { "order": null, "relations_precision": null, "relations_recall": null },
    "storage_efficiency": null,
    "event_loss_rate": null,
    "persistence_latency_ms": { "p50": null, "p95": null },
    "crash_recovery_rate": null
  }
}
```

The zero seed and budget in this template are structural examples, not run measurements. The all-zero hashes and commit are template tokens; a real result must replace them with recorded provenance. All measured numbers come from runs.
