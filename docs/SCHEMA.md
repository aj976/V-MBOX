# SCHEMA — V-MBOX

All persisted structures use **canonical JSON** (UTF-8, keys sorted, no insignificant whitespace, integers as integers, timestamps as integer nanoseconds since Unix epoch UTC) so hashes are reproducible. Field names are `snake_case`.

Schema version: `1`. Every segment and manifest records it.

## 1. Event record

```json
{
  "schema_version": 1,
  "event_id": "34d95801-91cf-5473-bba1-8e0641035cf6",
  "session_id": "00000000-0000-4000-8000-000000000001",
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
| `seq` | Strictly increasing per session, assigned by the normalizer *before* selection, in raw-trace line order. Gaps in persisted `seq` are therefore meaningful: either dropped by selection (recorded in tombstone/selection stats) or lost |
| `event_id` | UUIDv5 with namespace UUID `session_id` and name the base-10 `seq` with no leading zeros. Replay retains the trace `session_id` and `event_id`; each strategy run has its own `run_id` |
| `boot_id` | Derived from system boot time; changes after reboot |
| `ts_source` | `etw_qpc`, `sysmon_utc`, `wallclock`, `replay`. Timestamps are never assumed trustworthy (see `DESIGN.md` threat model) |
| `provenance` | `observed` (directly reported by a source), `derived` (computed from observed events, e.g. lineage), `inferred` (heuristic). Only `observed` is allowed on raw events; derived/inferred appear in reconstruction output |
| `pid`, `ppid`, `process`, `process.cmdline_hash` | Nullable only when `capture.status` is `partial` or category is `meta`. Never substitute `0`, `-1`, or empty string for missing data. An `ok` non-meta event requires all four |
| `process.cmdline` | Nullable. Raw text stored only with the explicit local-only opt-in; otherwise only its hash is stored when available. Selection and priority rules cannot depend on raw command-line content without that opt-in |
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

### Raw trace (M2)

`<trace>.jsonl` is canonical JSON Lines: each line is exactly `canonical_json(object) + LF` in UTF-8. Line 1 is a header. Every later line is one unfiltered source event in arrival order. This order alone determines `seq` in the normalizer; no sorting by timestamps or source. This example is a format template, not captured output:

```text
{"boot_id":"boot-example","collector_version":"0.1.0","config_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","host":{"windows_build":"not measured"},"raw_cmdline_opt_in":false,"session_id":"00000000-0000-4000-8000-000000000001","sources":["sysmon"],"sysmon_config_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","trace_format_version":1,"trace_id":"00000000-0000-4000-8000-000000000002"}
{"event_type":"PROC_START","payload":{"CommandLineHash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","Image":"C:\\example.exe","ParentProcessId":"1","ProcessId":"2","UtcTime":"2026-01-01 00:00:00.000"},"receipt_ts_ns":1767225600000000000,"source":"sysmon"}
```

Header keys are exactly `trace_format_version` (integer 1), `trace_id` (UUID), `session_id` (UUID), `boot_id` (string), `sources` (list of source tags), `collector_version` (string), `config_hash` (SHA-256 tag), `sysmon_config_hash` (SHA-256 tag or null if Sysmon unused), `host` (sanitized object containing `windows_build` only), and `raw_cmdline_opt_in` (boolean). Source-event keys are exactly `source`, `event_type`, `receipt_ts_ns` (integer Unix nanoseconds when received), and `payload` (source-native object). The source tag must occur in the header list. An unknown source event type is an explicit normalization error; it is never silently skipped.

By default, a source `CommandLine` field is replaced with `CommandLineHash` (`sha256:` over its exact UTF-8 bytes) before persistence. If the raw-text opt-in is true, both fields may be present; such traces are local-only and must never be committed. The header records the choice. Absence of both means `cmdline_hash: null` and a `partial` normalized event. This redaction does not filter source events.

`<trace>.jsonl.sha256` contains exactly one canonical JSON line: `{"sha256":"sha256:<64 lowercase hex>"}`. The digest covers the exact trace file bytes, including every LF; it is never embedded in the trace. Trace and sidecar are write-once. A missing sidecar, malformed/torn line, noncanonical line, or digest mismatch makes the trace incomplete or invalid, never complete.

Live-versus-replay identity and overflow `CAPTURE_GAP` behavior are **unverified until run on Windows VM**.
ETW task-name mapping and QPC timestamp conversion are also **unverified until run on Windows VM**. The normalizer rejects unknown ETW event types rather than guessing their meaning; receipt wallclock time is labeled `wallclock`, never `etw_qpc`.

## 2. Session manifest

Written at session start, hashed into the chain genesis.
The write-once file `manifest.json` contains exactly `canonical_json(manifest)` with no trailing newline; these exact bytes are the `H(0)` input.

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

`journal.bin` is a fixed-capacity ring of exactly `journal_bytes`, including its 64-byte control area. All multibyte integers are unsigned big-endian. The first 64 bytes are two 32-byte cursor slots. Each slot is `[u64 generation][u32 oldest_offset][u32 write_offset][u32 used_bytes][u64 evicted_frames][u32 crc32]`. Offsets are relative to the data area that begins at byte 64; CRC32 covers the first 28 slot bytes. A zeroed slot with bad CRC is unused. Recovery selects the highest-generation valid slot; if neither is valid, the journal is incomplete. The writer persists frame bytes before publishing the alternate cursor slot and flushes each phase. `used_bytes` distinguishes an empty ring and bounds the scan; at least one byte remains free.

Data frames are `[u32 length][u32 crc32][payload = canonical event JSON]`, where CRC32 covers payload bytes. Frames never cross the end of the data area. At wrap, `[u32 length=0][u32 crc32=0]` marks the unused tail when at least eight bytes remain; any following tail bytes are zero padding. If fewer than eight bytes remain, the entire tail is zero padding. Tail padding counts toward `used_bytes`; the reader wraps to offset zero. An overwritten oldest frame advances `oldest_offset` and increments `evicted_frames`; this count is reported as a retention limit. A bad frame CRC, short length, invalid padding, or noncanonical payload ends valid recovery and is reported as an incomplete write. A crash during overwrite can invalidate previously indexed ring content; recovery must report that gap rather than accept the journal as complete.

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

The header and footer lines each include their terminating LF. Body lengths are unsigned big-endian u32 values. `record_count` tells the reader exactly how many frames precede the footer; no trailing bytes are allowed. A segment is nonempty, with ascending `seq`, one session ID, and `ts_start_ns`/`ts_end_ns` equal to the minimum/maximum event timestamps in the body. `selection_stats` is an object with nonnegative integer `seen`, `kept`, `dropped_by_policy`, and `promoted_by_context`, plus `by_type` mapping event-type strings to nonnegative integer counts.

Chain: `H(i) = SHA-256( H(i-1) || S(i) )` where `H(i-1)` is the raw 32-byte digest and `S(i)` = header bytes ‖ body bytes (exactly as stored, canonical). `H(0)` = SHA-256 of the canonical session manifest. The `prev_hash`, `segment_hash`, and `body_sha256` text fields use lowercase `sha256:<64 hex>`.

`selection_stats` (per segment): `seen`, `kept`, `dropped_by_policy`, `by_type` counts, `promoted_by_context`. This lets reports separate "dropped on purpose" from "lost".

## 5. Tombstone

When the budget forces eviction, a sealed segment body is deleted and replaced by `seg_<index>.tomb`:

```json
{
  "index": 12, "seq_start": 0, "seq_end": 0, "record_count": 0,
  "ts_start_ns": 0, "ts_end_ns": 0,
  "prev_hash": "sha256:...", "segment_hash": "sha256:...",
  "evicted_reason": "budget", "evicted_ts_ns": 0,
  "tombstone_hash": "sha256:c5a987e9c14cdce4c5104976d93f9334194b7f6b7602b9897753d56d0a33930c"
}
```

`tombstone_hash` is SHA-256 of `canonical_json` over every other tombstone field. It catches accidental corruption and byte flips in tombstone metadata. The chain still verifies across tombstones because `segment_hash` is retained. The tombstoned content itself is no longer verifiable or recoverable, and the report says so. A host attacker can rewrite a tombstone and recompute this unkeyed checksum; only an external anchor can constrain a rewritten `segment_hash`.

## 6. Checkpoint and anchor receipt

Checkpoint (host → anchor), format template:

```json
{ "session_id": "uuid", "segment_index": 12, "segment_hash": "sha256:...", "seq_end": 0, "host_ts_ns": 0 }
```

Receipt (anchor → host, stored by both). Format template only: the zero signature below is not a real signature.

```json
{
  "checkpoint": { "session_id": "uuid", "segment_index": 12, "segment_hash": "sha256:...", "seq_end": 0, "host_ts_ns": 0 },
  "anchor_ts_ns": 0,
  "anchor_seq": 0,
  "prev_receipt_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "signature": "ed25519:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
}
```

The Ed25519 message is exactly `b"vmbox-receipt-v1\n" + canonical_json(receipt without signature)`, with no trailing LF. `signature` is `ed25519:` plus exactly 128 lowercase hexadecimal characters encoding the 64 signature bytes; uppercase and noncanonical encodings are invalid. `anchor_seq` starts at 0 and increases by one **per session_id**. The first `prev_receipt_hash` is `sha256:` plus 64 zeros. Each later `prev_receipt_hash` is SHA-256 of the full canonical signed previous receipt (including its signature), without a trailing LF. The host checks signatures with the anchor public key only. The manifest's `anchor.pubkey_fingerprint` is SHA-256 of the raw 32-byte Ed25519 public key.

Receipts are write-once canonical JSON files without a trailing LF, named `receipts/<session_id>/receipt_<anchor_seq:08d>.json` on both host and anchor. The anchor persists and fsyncs a receipt before returning it. Resubmitting an identical checkpoint returns exactly the same receipt and creates no new file. A new checkpoint must have `segment_index` greater than the last accepted one. A conflicting hash at the same index is rejected and recorded in a write-once anchor-side `equivocations/<session_id>/conflict_<segment_index:08d>_<rejected_checkpoint_sha256>.json` file. That file contains canonical JSON (no LF) with exactly `accepted_checkpoint`, `rejected_checkpoint`, and `anchor_ts_ns`; the filename digest covers the rejected checkpoint's canonical JSON bytes. Such a record documents a conflict, not intent or attribution.

An optional anchor-side export is a copy of the anchor's `receipts/` tree. The verifier checks both the host receipts and export, including signatures, sequence, previous-receipt hashes, and each referenced segment hash against the host's segment chain. If the host log is a strict prefix of the anchor export, it reports `host receipts end at anchor_seq N, anchor has M` and marks the missing host tail incomplete. A mismatched shared prefix fails verification. Without an anchor export, the signed host range is `unconfirmed against anchor state`: host-side receipts alone cannot detect a truncated tail. Second-VM transport and power-loss durability are **unverified until run on the second VM**.

## 7. Reconstruction output

```json
{
  "timeline": [
    { "ref": "event_id", "ts_ns": 0, "integrity": "anchored" }
  ],
  "relations": [
    {
      "relation_id": "r1",
      "type": "parent_of",
      "from": "event_id", "to": "event_id",
      "provenance": "derived",
      "basis": "ppid match",
      "confidence": "medium"
    }
  ],
  "gaps": [ { "kind": "seq_gap", "seq_range": [0,0], "ts_range_ns": [0,0] } ],
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
  "anchor": { "nonce": "run_nonce", "event_type": "PROC_START", "image_regex": ".*vmbox_anchor_run_nonce\\.exe$" },
  "steps": [
    {
      "step_id": "s1",
      "description": "launch stager",
      "match": { "event_type": "PROC_START", "image_regex": ".*stager\\.exe$", "ts_window_ns": [0, 1000000000], "pid_lineage": null },
      "relevance": "attack"
    }
  ],
  "benign_workload": "browse_office_build_v1",
  "review_resolutions": []
}
```

`ts_window_ns` is `[start_offset_ns, end_offset_ns]`: integer nanosecond offsets, inclusive, relative to the unique anchor event's `ts_ns` (`t0`). The scenario runner starts each run by launching a marker with a per-run nonce in its image name and records that nonce in `anchor`. The matcher requires exactly one trace event with the anchor `event_type`, `image_regex`, and nonce in its process image. Zero or multiple anchors are hard errors; the run is unlabeled. Raw command-line content is not required. Windows and their stated tolerance are chosen from the scenario script's intended timing before any strategy is run. After freeze, changing a window creates a new label version.

Step identity is `event_type` **and** `image_regex`, plus `pid_lineage` where relevant; time only narrows candidates. `pid_lineage` is either `null` or `{ "step_id": "earlier_step", "relation": "same_pid" }` / `{ "step_id": "earlier_step", "relation": "child_of" }`. The first relation compares event PIDs; the second compares the candidate's PPID to the earlier matched event's PID. A lineage-dependent step cannot resolve until its parent step has a unique match or a reviewed resolution. Missing attack steps are collection misses, not selection misses.

If multiple candidates remain, the matcher writes `match_review.json` with `run_id`, `ambiguous` entries (`step_id`, `candidate_event_ids`, `resolution`). A resolution is `null` until manual review, then `{ "step_id": "s1", "event_id": "uuid", "reviewer": "name", "reviewed_ts_ns": 123 }`. The reviewer and timestamp are required; each resolved event ID must be one of the listed candidates. Before freezing `labels.json`, copy final resolutions to its required `review_resolutions` array, so the label hash covers the review decisions. `match_review.json` is a pre-freeze workpaper; once labels are frozen, any review or window change creates a new label version. The label example above is a template, not a measurement.

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
