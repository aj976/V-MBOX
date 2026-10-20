"""Offline unbounded reference using the real journal and sealed segment format."""

import os
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from vmbox.collect.trace import read_trace
from vmbox.eval.labels import read_labels
from vmbox.eval.matching import match_labels
from vmbox.eval.metrics import storage_efficiency
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.normalize.normalizer import Normalizer
from vmbox.schema import (
    EvaluationMetrics,
    EvaluationResult,
    PersistenceLatency,
    ReconstructionAccuracy,
    SessionManifest,
    ToolVersions,
)
from vmbox.store.budget import retained_bytes
from vmbox.store.journal import append_journal, create_journal, recover_journal
from vmbox.store.manifest import write_manifest
from vmbox.store.segment import SelectionStats, encode_segment, seal_segment


def run_unbounded(trace_path: Path, labels_path: Path, output_dir: Path, *,
                  journal_bytes: int, git_commit: str, git_dirty: bool,
                  strategy_rules_version: str, tool_versions: ToolVersions) -> EvaluationResult:
    """Replay one frozen trace; caller supplies recorded provenance, never defaults."""
    header, records = read_trace(trace_path)
    labels = read_labels(labels_path)
    normalizer = Normalizer(header)
    events = [normalizer.normalize(record) for record in records]
    if not events:
        raise ValueError("unbounded run requires at least one event")
    matched = match_labels(labels, events)
    if matched.blocked or any(item.resolution is None for item in matched.review.ambiguous):
        raise ValueError("frozen labels have unresolved matches")
    if journal_bytes < 80:
        raise ValueError("journal too small")
    by_type: dict[str, int] = {}
    for event in events:
        by_type[event.event_type] = by_type.get(event.event_type, 0) + 1
    stats = SelectionStats(len(events), len(events), 0, by_type, 0)
    manifest = SessionManifest(
        schema_version=1, mode="offline_eval", session_id=header.session_id,
        boot_id=header.boot_id, host=header.host["windows_build"],
        start_ts_ns=min(event.ts_ns for event in events),
        collector_version=header.collector_version, config_hash=header.config_hash,
        strategy="unbounded", budget_bytes=journal_bytes, journal_bytes=journal_bytes,
        anchor=None,
    )
    initial, _ = encode_segment(index=0, events=events,
                                prev_hash="sha256:" + manifest_genesis(manifest).hex(),
                                strategy="unbounded", selection_stats=stats)
    # This manifest allocation is derived from exact serialized size. The experimental
    # unbounded result has no selection budget, so its budget fields remain null.
    manifest = replace(manifest, budget_bytes=journal_bytes + len(initial))
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True)
    write_manifest(output_dir / "manifest.json", manifest)
    journal_path = output_dir / "journal.bin"
    create_journal(journal_path, journal_bytes)
    for event in events:
        append_journal(journal_path, event)
    seal_segment(output_dir / "seg_00000000.vseg", index=0, events=events,
                 prev_hash="sha256:" + manifest_genesis(manifest).hex(),
                 strategy="unbounded", selection_stats=stats)
    chain = verify_chain(output_dir, manifest)
    journal = recover_journal(journal_path)
    if chain.status != "ok" or journal.incomplete_reason is not None:
        raise ValueError("offline replay evidence failed local verification")
    retained = retained_bytes(output_dir)
    if retained != manifest.budget_bytes:
        raise ValueError("serialized segment size changed after manifest finalization")
    attack_steps = {step.step_id for step in labels.steps if step.relevance == "attack"}
    collected = attack_steps & set(matched.matched)
    # Every normalized event was sealed; labels that were collected are recoverable.
    persisted = collected
    metrics = EvaluationMetrics(
        evidence_coverage=len(persisted) / len(collected) if collected else None,
        collection_coverage=len(collected) / len(attack_steps) if attack_steps else None,
        reconstruction_accuracy=ReconstructionAccuracy(None, None, None),
        storage_efficiency=storage_efficiency(len(persisted), retained),
        event_loss_rate=None, persistence_latency_ms=PersistenceLatency(None, None),
        crash_recovery_rate=None,
    )
    result = EvaluationResult(
        run_id=str(uuid4()), scenario_id=labels.scenario_id, seed=labels.seed,
        strategy="unbounded", budget_bytes=None, budget_fraction_of_full=None,
        bytes_retained=retained,
        trace_hash="sha256:" + sha256(trace_path.read_bytes()).hexdigest(),
        label_hash="sha256:" + sha256(labels_path.read_bytes()).hexdigest(),
        config_hash=header.config_hash, git_commit=git_commit, git_dirty=git_dirty,
        strategy_rules_version=strategy_rules_version, tool_versions=tool_versions,
        metrics=metrics,
    )
    with (output_dir / "result.json").open("xb") as stream:
        stream.write(result.to_json())
        stream.flush()
        os.fsync(stream.fileno())
    return result
