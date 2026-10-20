"""Budgeted segment admission and safe eviction; no silent overrun."""

from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from vmbox.canonical import canonical_json
from vmbox.integrity.chain import ChainVerification, verify_chain
from vmbox.integrity.genesis import manifest_genesis
from vmbox.integrity.segment import verify_segment
from vmbox.schema import Event, SessionManifest
from vmbox.store.segment import SegmentFooter, SelectionStats, encode_segment, seal_segment
from vmbox.store.tombstone import evict_segment, make_tombstone


class BudgetExhausted(RuntimeError):
    """No safe write/eviction sequence fits the configured evidence budget."""


def retained_bytes(directory: Path) -> int:
    """Count journal, sealed bodies, tombstones, and in-flight temp files."""
    paths = [directory / "journal.bin", *directory.glob("seg_*.*")]
    return sum(path.stat().st_size for path in paths if path.is_file())


class BudgetedSegmentStore:
    def __init__(self, directory: Path, manifest: SessionManifest,
                 eviction_score: Callable[[tuple[Event, ...]], float] | None = None) -> None:
        self.directory = directory
        self.manifest = manifest
        self.eviction_score = eviction_score
        if not (directory / "journal.bin").is_file():
            raise ValueError("budget requires an initialized journal")
        if retained_bytes(directory) > manifest.budget_bytes:
            raise BudgetExhausted("existing evidence exceeds budget")

    def _verified_chain(self) -> ChainVerification:
        chain = verify_chain(self.directory, self.manifest)
        if chain.status != "ok":
            raise ValueError(f"cannot write to {chain.status} evidence: {chain.reason}")
        return chain

    def _evict_candidate(self, chain: ChainVerification, evicted_ts_ns: int) -> None:
        candidates = [entry for entry in chain.entries if entry.kind == "segment"]
        if not candidates:
            raise BudgetExhausted("budget contains no segment eligible for eviction")
        if self.eviction_score is None:
            candidate = candidates[0]
        else:
            scored: list[tuple[float, int]] = []
            for entry in candidates:
                previous = ("sha256:" + manifest_genesis(self.manifest).hex()
                            if entry.index == 0 else chain.entries[entry.index - 1].segment_hash)
                path = self.directory / f"seg_{entry.index:08d}.vseg"
                verified = verify_segment(path, previous)
                if verified.status != "ok":
                    raise ValueError("eviction candidate failed verification")
                scored.append((self.eviction_score(tuple(verified.events)), entry.index))
            candidate_index = min(scored)[1]
            candidate = chain.entries[candidate_index]
        index = candidate.index
        previous = ("sha256:" + manifest_genesis(self.manifest).hex() if index == 0
                    else chain.entries[index - 1].segment_hash)
        segment_path = self.directory / f"seg_{index:08d}.vseg"
        tomb_path = self.directory / f"seg_{index:08d}.tomb"
        verified = verify_segment(segment_path, previous)
        if verified.status != "ok" or verified.header is None or verified.footer is None:
            raise ValueError("eviction candidate failed verification")
        tomb = make_tombstone(verified.header, verified.footer, evicted_ts_ns)
        tomb_size = len(canonical_json(asdict(tomb))) + 1
        if retained_bytes(self.directory) + tomb_size > self.manifest.budget_bytes:
            raise BudgetExhausted("insufficient headroom to publish tombstone before deletion")
        evict_segment(segment_path, tomb_path, previous, evicted_ts_ns)

    def seal(self, events: list[Event], strategy: str, selection_stats: SelectionStats,
             evicted_ts_ns: int) -> SegmentFooter:
        chain = self._verified_chain()
        index = len(chain.entries)
        raw, footer = encode_segment(index=index, events=events, prev_hash=chain.last_hash,
                                     strategy=strategy, selection_stats=selection_stats)
        if len(raw) + (self.directory / "journal.bin").stat().st_size > self.manifest.budget_bytes:
            raise BudgetExhausted("segment cannot fit even without retained segments")
        while retained_bytes(self.directory) + len(raw) > self.manifest.budget_bytes:
            self._evict_candidate(chain, evicted_ts_ns)
            chain = self._verified_chain()
        path = self.directory / f"seg_{index:08d}.vseg"
        actual = seal_segment(path, index=index, events=events, prev_hash=chain.last_hash,
                              strategy=strategy, selection_stats=selection_stats)
        if actual != footer:
            raise RuntimeError("segment bytes changed between budget check and seal")
        return actual
