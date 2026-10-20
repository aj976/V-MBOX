"""Schema version 1 models. docs/SCHEMA.md owns persisted formats."""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from hashlib import sha256
from math import isfinite
from typing import Any, Literal, TypeVar, get_args, get_origin, get_type_hints
from uuid import UUID, uuid5

from vmbox.canonical import canonical_json

ModelT = TypeVar("ModelT", bound="SchemaModel")
_HINT_CACHE: dict[type[SchemaModel], dict[str, Any]] = {}


def _model_hints(model_type: type[SchemaModel]) -> dict[str, Any]:
    if model_type not in _HINT_CACHE:
        _HINT_CACHE[model_type] = get_type_hints(model_type)
    return _HINT_CACHE[model_type]


def _valid_type(value: Any, annotation: Any) -> bool:
    origin = get_origin(annotation)
    if origin is None:
        if annotation is Any:
            return True
        if isinstance(annotation, type):
            return type(value) is annotation or (
                issubclass(annotation, SchemaModel) and isinstance(value, annotation)
            )
        return False
    if origin is Literal:
        return value in get_args(annotation)
    if origin in (list, tuple):
        args = get_args(annotation)
        return type(value) is origin and all(_valid_type(item, args[0]) for item in value)
    if origin is dict:
        key_type, val_type = get_args(annotation)
        return type(value) is dict and all(
            _valid_type(k, key_type) and _valid_type(v, val_type) for k, v in value.items()
        )
    if origin is type(None):
        return value is None
    return any(_valid_type(value, arg) for arg in get_args(annotation))


def _decode(value: Any, annotation: Any) -> Any:
    if isinstance(annotation, type) and issubclass(annotation, SchemaModel):
        return annotation.from_dict(value)
    origin = get_origin(annotation)
    if origin is list and type(value) is list:
        return [_decode(item, get_args(annotation)[0]) for item in value]
    if origin is dict and type(value) is dict:
        return {k: _decode(v, get_args(annotation)[1]) for k, v in value.items()}
    if origin is not None:
        for arg in get_args(annotation):
            if arg is type(None) and value is None:
                return None
            if isinstance(arg, type) and issubclass(arg, SchemaModel) and type(value) is dict:
                return arg.from_dict(value)
    return value


def _encode(value: Any) -> Any:
    if isinstance(value, SchemaModel):
        return value.to_dict()
    if isinstance(value, list):
        return [_encode(item) for item in value]
    if isinstance(value, dict):
        return {key: _encode(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class SchemaModel:
    def __post_init__(self) -> None:
        hints = _model_hints(type(self))
        for field in fields(self):
            value = getattr(self, field.name)
            if not _valid_type(value, hints[field.name]):
                raise ValueError(f"{type(self).__name__}.{field.name}: invalid type or value")

    @classmethod
    def from_dict(cls: type[ModelT], data: dict[str, Any]) -> ModelT:
        if type(data) is not dict:
            raise ValueError(f"{cls.__name__}: expected object")
        names = {field.name for field in fields(cls)}
        if set(data) != names:
            raise ValueError(
                f"{cls.__name__}: missing {sorted(names - set(data))}; "
                f"extra {sorted(set(data) - names)}"
            )
        hints = _model_hints(cls)
        decoded = {name: _decode(value, hints[name]) for name, value in data.items()}
        return cls(**decoded)

    def to_dict(self) -> dict[str, Any]:
        return {field.name: _encode(getattr(self, field.name)) for field in fields(self)}

    def to_json(self) -> bytes:
        return canonical_json(self.to_dict())


@dataclass(frozen=True)
class ProcessInfo(SchemaModel):
    image: str
    cmdline_hash: str | None
    cmdline: str | None


@dataclass(frozen=True)
class CaptureInfo(SchemaModel):
    source: str
    status: Literal["ok", "partial", "source_error", "dropped_upstream"]
    collector_version: str


EVENT_CATEGORIES = {
    "PROC_START": "process", "PROC_EXIT": "process",
    "NET_CONNECT": "network", "NET_CLOSE": "network",
    "MEM_REMOTE_THREAD": "memory", "MEM_PROCESS_ACCESS": "memory",
    "MEM_IMAGE_LOAD": "memory", "MEM_PROTECT_CHANGE": "memory",
    "CAPTURE_GAP": "meta", "COLLECTOR_START": "meta", "COLLECTOR_STOP": "meta",
}


@dataclass(frozen=True)
class Event(SchemaModel):
    schema_version: int
    event_id: str
    session_id: str
    boot_id: str
    seq: int
    ts_ns: int
    ts_source: Literal["etw_qpc", "sysmon_utc", "wallclock", "replay"]
    event_type: str
    category: str
    pid: int | None
    ppid: int | None
    process: ProcessInfo | None
    data: dict[str, Any]
    provenance: Literal["observed"]
    capture: CaptureInfo
    priority: int | float | None
    tags: list[str]

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.schema_version != 1 or self.seq < 0 or self.ts_ns < 0:
            raise ValueError("invalid version, seq or timestamp")
        if EVENT_CATEGORIES.get(self.event_type) != self.category:
            raise ValueError("invalid PID or event category")
        if any(value is not None and value < 0 for value in (self.pid, self.ppid)):
            raise ValueError("negative PID")
        if self.process is not None and not self.process.image:
            raise ValueError("empty process image")
        if self.process is not None and self.process.cmdline_hash == "":
            raise ValueError("empty command-line hash")
        missing = (self.pid is None or self.ppid is None or self.process is None
                   or self.process.cmdline_hash is None)
        if missing and self.capture.status != "partial" and self.category != "meta":
            raise ValueError("missing fields require partial capture or meta event")
        try:
            expected_id = str(uuid5(UUID(self.session_id), str(self.seq)))
        except ValueError as exc:
            raise ValueError("invalid session_id UUID") from exc
        if self.event_id != expected_id:
            raise ValueError("event_id must be UUIDv5(session_id, seq)")


@dataclass(frozen=True)
class AnchorInfo(SchemaModel):
    endpoint: str
    pubkey_fingerprint: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.endpoint.strip() or not self.pubkey_fingerprint.strip():
            raise ValueError("anchor requires endpoint and public key fingerprint")


@dataclass(frozen=True)
class SessionManifest(SchemaModel):
    schema_version: int
    mode: Literal["live", "offline_eval"]
    session_id: str
    boot_id: str
    host: str
    start_ts_ns: int
    collector_version: str
    config_hash: str
    strategy: str
    budget_bytes: int
    journal_bytes: int
    anchor: AnchorInfo | None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.schema_version != 1 or self.start_ts_ns < 0:
            raise ValueError("invalid manifest version or timestamp")
        if not 0 <= self.journal_bytes <= self.budget_bytes:
            raise ValueError("journal exceeds budget")
        if self.mode == "live" and self.anchor is None:
            raise ValueError("live session requires an anchor")


@dataclass(frozen=True)
class Checkpoint(SchemaModel):
    session_id: str
    segment_index: int
    segment_hash: str
    seq_end: int
    host_ts_ns: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if min(self.segment_index, self.seq_end, self.host_ts_ns) < 0:
            raise ValueError("negative checkpoint value")


@dataclass(frozen=True)
class Receipt(SchemaModel):
    checkpoint: Checkpoint
    anchor_ts_ns: int
    anchor_seq: int
    prev_receipt_hash: str
    signature: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.anchor_ts_ns < 0 or self.anchor_seq < 0:
            raise ValueError("negative receipt value")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.prev_receipt_hash) is None:
            raise ValueError("invalid previous receipt hash")
        if re.fullmatch(r"ed25519:[0-9a-f]{128}", self.signature) is None:
            raise ValueError("invalid Ed25519 signature encoding")


@dataclass(frozen=True)
class Tombstone(SchemaModel):
    index: int
    seq_start: int
    seq_end: int
    record_count: int
    ts_start_ns: int
    ts_end_ns: int
    prev_hash: str
    segment_hash: str
    evicted_reason: str
    evicted_ts_ns: int
    tombstone_hash: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if min(self.index, self.seq_start, self.seq_end, self.record_count,
               self.ts_start_ns, self.ts_end_ns, self.evicted_ts_ns) < 0:
            raise ValueError("negative tombstone value")
        content = {key: value for key, value in self.to_dict().items()
                   if key != "tombstone_hash"}
        expected = "sha256:" + sha256(canonical_json(content)).hexdigest()
        if self.tombstone_hash != expected:
            raise ValueError("tombstone hash mismatch")


@dataclass(frozen=True)
class TimelineEntry(SchemaModel):
    ref: str
    ts_ns: int
    integrity: Literal["anchored", "chained", "journal_only", "unverified", "tampered"]


@dataclass(frozen=True)
class Relation(SchemaModel):
    relation_id: str
    type: Literal["parent_of", "spawned_then_connected", "remote_thread_into", "temporal_proximity"]
    from_: str
    to: str
    provenance: Literal["derived", "inferred"]
    basis: str
    confidence: Literal["high", "medium", "low"]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Relation:
        if "from" not in data:
            raise ValueError("Relation: missing from")
        renamed = {"from_": data["from"], **{k: v for k, v in data.items() if k != "from"}}
        return super().from_dict(renamed)

    def to_dict(self) -> dict[str, Any]:
        return {"from" if k == "from_" else k: v for k, v in super().to_dict().items()}

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.type == "temporal_proximity" and (
            self.provenance != "inferred" or self.confidence == "high"
        ):
            raise ValueError("temporal proximity must be inferred and not high confidence")


@dataclass(frozen=True)
class Gap(SchemaModel):
    kind: Literal["seq_gap", "capture_gap", "interruption", "tombstone", "incomplete_write"]
    reason: Literal["missing_sequence", "collector_reported_gap", "no_stop_marker",
                    "budget_eviction", "torn_frame_no_header",
                    "crc_failure_unreadable_payload", "journal_unreadable",
                    "journal_missing", "chain_incomplete", "chain_tampered",
                    "receipt_verification_failed"]
    seq_range: list[int] | None
    ts_range_ns: list[int] | None
    last_valid_seq: int | None
    last_valid_ts_ns: int | None
    next_valid_seq: int | None
    next_valid_ts_ns: int | None

    def __post_init__(self) -> None:
        super().__post_init__()
        allowed = {
            "seq_gap": {"missing_sequence"},
            "capture_gap": {"collector_reported_gap"},
            "tombstone": {"budget_eviction"},
            "interruption": {"no_stop_marker"},
            "incomplete_write": {"torn_frame_no_header",
                                 "crc_failure_unreadable_payload", "journal_unreadable",
                                 "journal_missing", "chain_incomplete", "chain_tampered",
                                 "receipt_verification_failed"},
        }
        if self.reason not in allowed[self.kind]:
            raise ValueError("gap reason does not match kind")
        if self.kind in {"seq_gap", "capture_gap", "tombstone"} and (
            self.seq_range is None or self.ts_range_ns is None
        ):
            raise ValueError("observed or tombstone gaps require both ranges")
        for value in (self.seq_range, self.ts_range_ns):
            if value is not None and (len(value) != 2 or value[0] < 0
                                      or value[0] > value[1]):
                raise ValueError("invalid gap range")
        for seq, ts in ((self.last_valid_seq, self.last_valid_ts_ns),
                        (self.next_valid_seq, self.next_valid_ts_ns)):
            if (seq is None) != (ts is None) or (seq is not None and seq < 0) \
                    or (ts is not None and ts < 0):
                raise ValueError("invalid gap boundary")


@dataclass(frozen=True)
class Reconstruction(SchemaModel):
    reconstruction_format_version: int
    timeline: list[TimelineEntry]
    relations: list[Relation]
    gaps: list[Gap]
    limitations: list[str]

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.reconstruction_format_version != 1:
            raise ValueError("unsupported reconstruction format version")
        if any(gap.seq_range is None or gap.ts_range_ns is None for gap in self.gaps) \
                and not any("unknown" in item.lower() for item in self.limitations):
            raise ValueError("unknown gap bounds require an explicit limitation")


@dataclass(frozen=True)
class Report(SchemaModel):
    report_format_version: int
    generated_at: int
    tool_versions: dict[str, str | None]
    session: dict[str, Any]
    evidence_identity: dict[str, Any]
    verify_result: dict[str, Any]
    recovery_summary: dict[str, Any]
    integrity_counts: dict[str, int]
    reconstruction: Reconstruction
    event_details: list[dict[str, Any]]
    limitations: list[str]
    content_hash: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.report_format_version != 1 or self.generated_at < 0:
            raise ValueError("invalid report format or timestamp")
        if set(self.tool_versions) != {"python", "vmbox"} \
                or type(self.tool_versions["python"]) is not str \
                or not self.tool_versions["python"]:
            raise ValueError("invalid report tool versions")
        if not self.limitations or any(not item.strip() for item in self.limitations):
            raise ValueError("report requires non-empty limitations")
        if not set(self.reconstruction.limitations).issubset(self.limitations):
            raise ValueError("report cannot remove reconstruction limitations")
        if set(self.integrity_counts) != {
            "anchored", "chained", "journal_only", "unverified", "tampered"
        } or any(count < 0 for count in self.integrity_counts.values()) \
                or self.integrity_counts["tampered"] > 1:
            raise ValueError("invalid integrity counts")
        if set(self.verify_result) != {"output", "exit_code"} \
                or type(self.verify_result["output"]) is not str \
                or self.verify_result["exit_code"] not in (0, 1, 2, 3):
            raise ValueError("invalid verify result")
        if set(self.session) != {
            "host", "boot_id", "session_id", "mode", "strategy", "budget_bytes",
            "collector_version", "pubkey_fingerprint",
        }:
            raise ValueError("invalid report session summary")
        if any(type(self.session[key]) is not str or not self.session[key] for key in
               ("host", "boot_id", "session_id", "strategy", "collector_version")) \
                or self.session["mode"] not in ("live", "offline_eval") \
                or type(self.session["budget_bytes"]) is not int \
                or self.session["budget_bytes"] < 0 \
                or (self.session["pubkey_fingerprint"] is not None and
                    type(self.session["pubkey_fingerprint"]) is not str):
            raise ValueError("invalid report session values")
        if set(self.evidence_identity) != {"chain_head_hash", "segment_count",
                                          "tombstone_count", "hash_inputs"}:
            raise ValueError("invalid evidence identity")
        if type(self.evidence_identity["chain_head_hash"]) is not str or any(
            type(self.evidence_identity[key]) is not int or self.evidence_identity[key] < 0
            for key in ("segment_count", "tombstone_count")
        ) or type(self.evidence_identity["hash_inputs"]) is not list:
            raise ValueError("invalid evidence identity values")
        for item in self.evidence_identity["hash_inputs"]:
            if type(item) is not dict or set(item) != {"path", "sha256"} \
                    or type(item["path"]) is not str or type(item["sha256"]) is not str \
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", item["sha256"]) is None:
                raise ValueError("invalid evidence hash input")
        if set(self.recovery_summary) != {"status", "chain_status", "journal_status",
                                         "receipt_status", "recovered_events",
                                         "journal_evicted_frames"}:
            raise ValueError("invalid recovery summary")
        if self.recovery_summary["status"] not in ("ok", "incomplete", "tampered") \
                or type(self.recovery_summary["recovered_events"]) is not int \
                or self.recovery_summary["recovered_events"] < 0:
            raise ValueError("invalid recovery status")
        if self.integrity_counts["tampered"] != int(
            self.recovery_summary["status"] == "tampered"
        ):
            raise ValueError("tampered count must match recovery status")
        for event in self.event_details:
            if type(event) is not dict or set(event) != {
                "event_id", "seq", "pid", "event_type", "image", "cmdline_hash",
                "cmdline",
            } or type(event["event_id"]) is not str or type(event["seq"]) is not int:
                raise ValueError("invalid report event detail")
        if any(event["cmdline"] is not None for event in self.event_details) and not any(
            "contains raw command lines, do not share" in item.lower()
            for item in self.limitations
        ):
            raise ValueError("raw command lines require a sharing limitation")
        content = {key: value for key, value in self.to_dict().items()
                   if key not in {"generated_at", "content_hash"}}
        expected = "sha256:" + sha256(canonical_json(content)).hexdigest()
        if self.content_hash != expected:
            raise ValueError("report content hash mismatch")


@dataclass(frozen=True)
class LabelAnchor(SchemaModel):
    nonce: str
    event_type: str
    image_regex: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.nonce or self.nonce not in self.image_regex or not self.event_type:
            raise ValueError("anchor must identify its nonce and event type")
        re.compile(self.image_regex)


@dataclass(frozen=True)
class PidLineage(SchemaModel):
    step_id: str
    relation: Literal["same_pid", "child_of"]


@dataclass(frozen=True)
class StepMatch(SchemaModel):
    event_type: str
    image_regex: str
    ts_window_ns: list[int]
    pid_lineage: PidLineage | None

    def __post_init__(self) -> None:
        super().__post_init__()
        if len(self.ts_window_ns) != 2 or self.ts_window_ns[0] > self.ts_window_ns[1]:
            raise ValueError("invalid time window")
        if not self.event_type:
            raise ValueError("empty event type")
        re.compile(self.image_regex)


@dataclass(frozen=True)
class LabelStep(SchemaModel):
    step_id: str
    description: str
    match: StepMatch
    relevance: Literal["attack", "benign"]


@dataclass(frozen=True)
class ReviewResolution(SchemaModel):
    step_id: str
    event_id: str
    reviewer: str
    reviewed_ts_ns: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.step_id or not self.event_id or not self.reviewer or self.reviewed_ts_ns < 0:
            raise ValueError("incomplete review resolution")


@dataclass(frozen=True)
class ReviewCandidate(SchemaModel):
    event_id: str
    seq: int
    ts_ns: int
    event_type: str
    image: str
    pid: int | None
    ppid: int | None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.seq < 0 or self.ts_ns < 0 or not self.event_type or not self.image:
            raise ValueError("invalid review candidate")


@dataclass(frozen=True)
class AmbiguousMatch(SchemaModel):
    step_id: str
    candidates: list[ReviewCandidate]
    resolution: ReviewResolution | None

    def __post_init__(self) -> None:
        super().__post_init__()
        if len(self.candidates) < 2 or len({item.event_id for item in self.candidates}) != len(
            self.candidates
        ):
            raise ValueError("ambiguous match needs distinct candidates")
        if self.resolution is not None and (
            self.resolution.step_id != self.step_id
            or self.resolution.event_id not in {item.event_id for item in self.candidates}
        ):
            raise ValueError("review resolution must select a candidate")


@dataclass(frozen=True)
class MatchReview(SchemaModel):
    run_id: str
    ambiguous: list[AmbiguousMatch]

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.run_id or len({item.step_id for item in self.ambiguous}) != len(
            self.ambiguous
        ):
            raise ValueError("invalid review run or duplicate step")


@dataclass(frozen=True)
class GroundTruthLabel(SchemaModel):
    scenario_id: str
    run_id: str
    seed: int
    anchor: LabelAnchor
    steps: list[LabelStep]
    benign_workload: str
    review_resolutions: list[ReviewResolution]

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.seed < 0 or not self.scenario_id or not self.run_id:
            raise ValueError("invalid label identity")
        seen: set[str] = set()
        for step in self.steps:
            if not step.step_id or step.step_id in seen:
                raise ValueError("duplicate or empty step_id")
            if step.step_id == "anchor":
                raise ValueError("anchor is a reserved step_id")
            if (step.match.pid_lineage is not None
                    and step.match.pid_lineage.step_id not in seen | {"anchor"}):
                raise ValueError("PID lineage must reference an earlier step")
            seen.add(step.step_id)
        reviewed: set[str] = set()
        for resolution in self.review_resolutions:
            if resolution.step_id not in seen or resolution.step_id in reviewed:
                raise ValueError("review resolution has unknown or duplicate step")
            reviewed.add(resolution.step_id)


@dataclass(frozen=True)
class ReconstructionAccuracy(SchemaModel):
    order: float | None
    relations_precision: float | None
    relations_recall: float | None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.order is not None and not -1 <= self.order <= 1:
            raise ValueError("order agreement out of range")
        for value in (self.relations_precision, self.relations_recall):
            if value is not None and not 0 <= value <= 1:
                raise ValueError("relation metric out of range")


@dataclass(frozen=True)
class PersistenceLatency(SchemaModel):
    p50: float | None
    p95: float | None

    def __post_init__(self) -> None:
        super().__post_init__()
        if any(value is not None and value < 0 for value in (self.p50, self.p95)):
            raise ValueError("negative latency")


@dataclass(frozen=True)
class EvaluationMetrics(SchemaModel):
    evidence_coverage: float | None
    collection_coverage: float | None
    reconstruction_accuracy: ReconstructionAccuracy
    storage_efficiency: float | None
    event_loss_rate: float | None
    persistence_latency_ms: PersistenceLatency
    crash_recovery_rate: float | None

    def __post_init__(self) -> None:
        super().__post_init__()
        rates = (self.evidence_coverage, self.collection_coverage,
                 self.event_loss_rate, self.crash_recovery_rate)
        if any(value is not None and not 0 <= value <= 1 for value in rates):
            raise ValueError("rate out of range")
        if self.storage_efficiency is not None and self.storage_efficiency < 0:
            raise ValueError("negative storage efficiency")


@dataclass(frozen=True)
class ToolVersions(SchemaModel):
    python: str
    vmbox: str
    lockfile_hash: str
    windows_build: str
    sysmon_version: str
    etw_pywintrace: str | None


@dataclass(frozen=True)
class EvaluationResult(SchemaModel):
    run_id: str
    scenario_id: str
    seed: int
    strategy: Literal["unbounded", "fixed", "priority", "context_aware", "fifo_ring"]
    budget_bytes: int | None
    budget_fraction_of_full: float | None
    bytes_retained: int | None
    trace_hash: str
    label_hash: str
    config_hash: str
    git_commit: str
    git_dirty: bool
    strategy_rules_version: str
    tool_versions: ToolVersions
    metrics: EvaluationMetrics

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.seed < 0:
            raise ValueError("negative seed or budget")
        if self.strategy == "unbounded":
            if self.budget_bytes is not None or self.budget_fraction_of_full is not None:
                raise ValueError("unbounded strategy has no budget or fraction")
        elif (self.budget_bytes is None or self.budget_bytes < 0
              or self.budget_fraction_of_full is None
              or not isfinite(self.budget_fraction_of_full)
              or self.budget_fraction_of_full < 0):
            raise ValueError("budgeted strategy requires nonnegative budget and fraction")
        if self.bytes_retained is not None and self.bytes_retained < 0:
            raise ValueError("negative retained bytes")


@dataclass(frozen=True)
class EvaluationResultV2(EvaluationResult):
    result_format_version: int
    set_role: Literal["tuning", "held_out"]

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.result_format_version != 2:
            raise ValueError("unsupported evaluation result format")
