"""Read-only M6 retention audit; no persisted schema or result is changed."""

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from vmbox.collect.trace import read_trace
from vmbox.eval.labels import read_labels
from vmbox.eval.matching import match_labels
from vmbox.integrity.chain import verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.segment import verify_segment
from vmbox.normalize.normalizer import Normalizer
from vmbox.schema import EvaluationResult, EvaluationResultV2
from vmbox.store.budget import retained_bytes
from vmbox.store.journal import recover_journal
from vmbox.store.manifest import read_manifest


@dataclass(frozen=True)
class RetentionAudit:
    strategy: str
    budget_bytes: int | None
    collected_steps: int
    sealed_steps: int
    journal_only_steps: int
    missing_steps: int
    tombstones: int
    journal_evicted_frames: int

    @property
    def sealed_coverage(self) -> float | None:
        return self.sealed_steps / self.collected_steps if self.collected_steps else None


def audit_run(trace_path: Path, labels_path: Path, directory: Path) -> RetentionAudit:
    """Separate hash-chained retention from recoverable, unverified journal retention."""
    trace_raw = trace_path.read_bytes()
    labels_raw = labels_path.read_bytes()
    result_raw = (directory / "result.json").read_bytes()
    result_data = json.loads(result_raw)
    result = (EvaluationResultV2.from_dict(result_data)
              if "result_format_version" in result_data else
              EvaluationResult.from_dict(result_data))
    if result.to_json() != result_raw:
        raise ValueError("noncanonical evaluation result")
    if result.trace_hash != "sha256:" + sha256(trace_raw).hexdigest():
        raise ValueError("result trace hash differs from source")
    if result.label_hash != "sha256:" + sha256(labels_raw).hexdigest():
        raise ValueError("result label hash differs from frozen labels")
    header, records = read_trace(trace_path)
    labels = read_labels(labels_path)
    normalizer = Normalizer(header)
    events = [normalizer.normalize(record) for record in records]
    matches = match_labels(labels, events)
    if matches.blocked or any(item.resolution is None for item in matches.review.ambiguous):
        raise ValueError("frozen labels have unresolved matches")
    manifest = read_manifest(directory / "manifest.json")
    if (manifest.strategy != result.strategy or manifest.session_id != header.session_id
            or manifest.config_hash != result.config_hash
            or manifest.config_hash != header.config_hash):
        raise ValueError("manifest and result/trace disagree")
    if result.bytes_retained != retained_bytes(directory):
        raise ValueError("result retained-byte count differs from evidence")
    chain = verify_chain(directory, manifest)
    if chain.status != "ok":
        raise ValueError(f"chain is {chain.status}: {chain.reason}")
    journal = recover_journal(directory / "journal.bin")
    if journal.incomplete_reason is not None:
        raise ValueError(f"journal is incomplete: {journal.incomplete_reason}")
    sealed_ids: set[str] = set()
    previous = "sha256:" + manifest_genesis(manifest).hex()
    for entry in chain.entries:
        if entry.kind == "segment":
            segment = verify_segment(directory / f"seg_{entry.index:08d}.vseg", previous)
            if segment.status != "ok":
                raise ValueError(f"segment {entry.index} is {segment.status}")
            sealed_ids.update(event.event_id for event in segment.events)
        previous = entry.segment_hash
    journal_ids = {event.event_id for event in journal.events}
    attack_steps = {step.step_id for step in labels.steps if step.relevance == "attack"}
    collected_ids = {event_id for step_id, event_id in matches.matched.items()
                     if step_id in attack_steps}
    sealed = collected_ids & sealed_ids
    journal_only = (collected_ids & journal_ids) - sealed_ids
    missing = collected_ids - sealed_ids - journal_ids
    return RetentionAudit(
        result.strategy, result.budget_bytes, len(collected_ids), len(sealed),
        len(journal_only), len(missing),
        sum(entry.kind == "tombstone" for entry in chain.entries),
        journal.evicted_frames,
    )
