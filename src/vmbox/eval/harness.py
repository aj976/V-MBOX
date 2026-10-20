"""Offline replay harness shared by the M5 baseline and later M6 strategies."""

import os
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from vmbox.collect.trace import read_trace
from vmbox.eval.coverage import coverage
from vmbox.eval.labels import read_labels
from vmbox.eval.matching import match_labels
from vmbox.eval.metrics import budget_fraction_of_full, event_loss_rate, storage_efficiency
from vmbox.eval.policies import PolicyStrategy
from vmbox.eval.strategy import EvaluationStrategy, SelectionOutcome
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.segment import verify_segment
from vmbox.normalize.normalizer import Normalizer
from vmbox.schema import (
    EvaluationMetrics,
    EvaluationResult,
    Event,
    PersistenceLatency,
    ReconstructionAccuracy,
    SessionManifest,
    ToolVersions,
)
from vmbox.store.budget import BudgetedSegmentStore, retained_bytes
from vmbox.store.journal import append_journal_many, create_journal, recover_journal
from vmbox.store.manifest import write_manifest
from vmbox.store.segment import encode_segment, seal_segment


def _validate_selection(source: tuple[Event, ...], outcome: SelectionOutcome) -> None:
    source_by_id = {event.event_id: event for event in source}
    selected_ids = [event.event_id for event in outcome.events]
    if len(source_by_id) != len(source) or len(set(selected_ids)) != len(selected_ids):
        raise ValueError("source and selected event IDs must be unique")
    if any(source_by_id.get(event.event_id) != event for event in outcome.events):
        raise ValueError("strategy returned an event outside the normalized stream")
    source_positions = {event.event_id: index for index, event in enumerate(source)}
    if selected_ids != sorted(selected_ids, key=source_positions.__getitem__):
        raise ValueError("strategy changed source event order")
    stats = outcome.stats
    if (stats.seen != len(source) or stats.kept != len(outcome.events)
            or stats.dropped_by_policy != len(source) - len(outcome.events)):
        raise ValueError("strategy selection statistics do not match its output")


def _persisted_event_ids(directory: Path, manifest: SessionManifest) -> set[str]:
    recovered = recover_journal(directory / "journal.bin")
    if recovered.incomplete_reason is not None:
        raise ValueError("offline replay journal failed recovery")
    identifiers = {event.event_id for event in recovered.events}
    chain = verify_chain(directory, manifest)
    if chain.status != "ok":
        raise ValueError("offline replay chain failed verification")
    previous = "sha256:" + manifest_genesis(manifest).hex()
    for entry in chain.entries:
        if entry.kind == "segment":
            path = directory / f"seg_{entry.index:08d}.vseg"
            verified = verify_segment(path, previous)
            if verified.status != "ok" or verified.footer is None:
                raise ValueError("offline replay segment failed verification")
            identifiers.update(event.event_id for event in verified.events)
        previous = entry.segment_hash
    return identifiers


def run_evaluation(trace_path: Path, labels_path: Path, output_dir: Path, *,
                   strategy: EvaluationStrategy, journal_bytes: int,
                   budget_bytes: int | None, unbounded_bytes_retained: int | None,
                   git_commit: str, git_dirty: bool,
                   tool_versions: ToolVersions) -> EvaluationResult:
    """Replay one frozen trace without exposing labels to the selection strategy."""
    header, records = read_trace(trace_path)
    labels = read_labels(labels_path)
    normalizer = Normalizer(header)
    events = tuple(normalizer.normalize(record) for record in records)
    if not events:
        raise ValueError("evaluation requires at least one event")
    matched = match_labels(labels, list(events))
    if matched.blocked or any(item.resolution is None for item in matched.review.ambiguous):
        raise ValueError("frozen labels have unresolved matches")
    if journal_bytes < 80:
        raise ValueError("journal too small")
    if any(len(event.to_json()) + 8 >= journal_bytes - 64 for event in events):
        raise ValueError("journal cannot hold an event frame")
    if strategy.name == "unbounded":
        if budget_bytes is not None or unbounded_bytes_retained is not None:
            raise ValueError("unbounded evaluation has no budget or full-size input")
        sealed_allowance = None
    else:
        if budget_bytes is None or budget_bytes < journal_bytes:
            raise ValueError("budgeted evaluation must fund its journal")
        if unbounded_bytes_retained is None or unbounded_bytes_retained <= 0:
            raise ValueError("budgeted evaluation requires measured unbounded bytes")
        sealed_allowance = budget_bytes - journal_bytes
    if isinstance(strategy, PolicyStrategy) and strategy.segment_events is not None:
        outcomes = strategy.select_batches(events, sealed_allowance)
        batches = tuple(events[start:start + strategy.segment_events]
                        for start in range(0, len(events), strategy.segment_events))
        if len(outcomes) != len(batches):
            raise ValueError("strategy batch count changed")
        for batch, selected_batch in zip(batches, outcomes, strict=True):
            _validate_selection(batch, selected_batch)
    else:
        outcomes = (strategy.select(events, sealed_allowance),)
        _validate_selection(events, outcomes[0])
    outcome = outcomes[0] if len(outcomes) == 1 else None
    manifest = SessionManifest(
        schema_version=1, mode="offline_eval", session_id=header.session_id,
        boot_id=header.boot_id, host=header.host["windows_build"],
        start_ts_ns=min(event.ts_ns for event in events),
        collector_version=header.collector_version, config_hash=header.config_hash,
        strategy=strategy.name, budget_bytes=budget_bytes or journal_bytes,
        journal_bytes=journal_bytes, anchor=None,
    )
    if strategy.name == "unbounded":
        if outcome is None:
            raise AssertionError("unbounded replay must use one segment")
        raw, _ = encode_segment(
            index=0, events=list(outcome.events),
            prev_hash="sha256:" + manifest_genesis(manifest).hex(),
            strategy=strategy.name, selection_stats=outcome.stats,
        )
        manifest = replace(manifest, budget_bytes=journal_bytes + len(raw))
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True)
    write_manifest(output_dir / "manifest.json", manifest)
    journal_path = output_dir / "journal.bin"
    create_journal(journal_path, journal_bytes)
    append_journal_many(journal_path, events)
    sealed_batches: list[SelectionOutcome] = []
    if any(item.events for item in outcomes):
        if strategy.name == "unbounded":
            if outcome is None:
                raise AssertionError("unbounded replay must use one segment")
            seal_segment(
                output_dir / "seg_00000000.vseg", index=0, events=list(outcome.events),
                prev_hash="sha256:" + manifest_genesis(manifest).hex(),
                strategy=strategy.name, selection_stats=outcome.stats,
            )
        else:
            scorer = (strategy.eviction_scorer(events)
                      if isinstance(strategy, PolicyStrategy) else None)
            segment_store = BudgetedSegmentStore(output_dir, manifest, eviction_score=scorer)
            for selected_batch in outcomes:
                if selected_batch.events:
                    segment_store.seal(
                        list(selected_batch.events), strategy.name, selected_batch.stats,
                        evicted_ts_ns=max(event.ts_ns for event in selected_batch.events),
                    )
                    sealed_batches.append(selected_batch)
    chain = verify_chain(output_dir, manifest)
    if chain.status != "ok":
        raise ValueError("offline replay chain failed verification")
    retained = retained_bytes(output_dir)
    if strategy.name == "unbounded" and retained != manifest.budget_bytes:
        raise ValueError("serialized segment size changed after manifest finalization")
    if retained > manifest.budget_bytes:
        raise ValueError("evaluation exceeded its evidence budget")
    persisted_ids = _persisted_event_ids(output_dir, manifest)
    attack_steps = {step.step_id for step in labels.steps if step.relevance == "attack"}
    collected_steps = attack_steps & set(matched.matched)
    persisted_steps = {
        step_id for step_id in collected_steps if matched.matched[step_id] in persisted_ids
    }
    coverage_result = coverage(attack_steps, collected_steps, persisted_steps)
    source_ids = {event.event_id for event in events}
    selected_ids = {event.event_id for item in outcomes for event in item.events}
    evicted_ids = {event.event_id for entry in chain.entries if entry.kind == "tombstone"
                   for event in sealed_batches[entry.index].events}
    accounted_drops = ((source_ids - selected_ids) | evicted_ids) - persisted_ids
    metrics = EvaluationMetrics(
        evidence_coverage=coverage_result.evidence_coverage,
        collection_coverage=coverage_result.collection_coverage,
        reconstruction_accuracy=ReconstructionAccuracy(None, None, None),
        storage_efficiency=storage_efficiency(len(persisted_steps), retained),
        event_loss_rate=event_loss_rate(source_ids, persisted_ids, accounted_drops),
        persistence_latency_ms=PersistenceLatency(None, None), crash_recovery_rate=None,
    )
    fraction = None
    if strategy.name != "unbounded":
        if budget_bytes is None or unbounded_bytes_retained is None:
            raise AssertionError("validated budget inputs became unavailable")
        fraction = budget_fraction_of_full(budget_bytes, unbounded_bytes_retained)
    result = EvaluationResult(
        run_id=str(uuid4()), scenario_id=labels.scenario_id, seed=labels.seed,
        strategy=strategy.name, budget_bytes=budget_bytes,
        budget_fraction_of_full=fraction,
        bytes_retained=retained,
        trace_hash="sha256:" + sha256(trace_path.read_bytes()).hexdigest(),
        label_hash="sha256:" + sha256(labels_path.read_bytes()).hexdigest(),
        config_hash=header.config_hash, git_commit=git_commit, git_dirty=git_dirty,
        strategy_rules_version=strategy.rules_version, tool_versions=tool_versions,
        metrics=metrics,
    )
    with (output_dir / "result.json").open("xb") as stream:
        stream.write(result.to_json())
        stream.flush()
        os.fsync(stream.fileno())
    return result
