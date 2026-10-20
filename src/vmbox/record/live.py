"""Live Sysmon recorder. Windows VM behavior remains unverified."""

import time
from collections import deque
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vmbox.anchor.client import SyncResult, sync_receipts
from vmbox.collect.trace import TraceHeader, TraceRecord
from vmbox.eval.policies import PolicyStrategy
from vmbox.normalize.normalizer import Normalizer
from vmbox.schema import AnchorInfo, Event, SessionManifest
from vmbox.store.budget import BudgetedSegmentStore
from vmbox.store.journal import append_journal_many, create_journal
from vmbox.store.manifest import write_manifest


class LiveRecorder:
    """Bound RAM windows; commit journal before selection and sealed segments."""

    SCORING_HISTORY_EVENTS = 8192

    def __init__(self, root: Path, header: TraceHeader, strategy: PolicyStrategy,
                 *, budget_bytes: int, journal_bytes: int, segment_events: int,
                 anchor_endpoint: str, anchor_public_key: Ed25519PublicKey,
                 anchor_auth_key: bytes, host: str, anchor_timeout: float = 1) -> None:
        from vmbox.anchor.receipt_crypto import public_key_fingerprint

        if root.exists() or segment_events <= 0 or journal_bytes >= budget_bytes \
                or anchor_timeout <= 0:
            raise ValueError("invalid or existing live recording output")
        self.root = root
        self.header = header
        self.normalizer = Normalizer(header)
        self.strategy = strategy
        self.segment_events = segment_events
        self.anchor_public_key = anchor_public_key
        self.anchor_auth_key = anchor_auth_key
        self.anchor_timeout = anchor_timeout
        self.manifest = SessionManifest(
            1, "live", header.session_id, header.boot_id, host, time.time_ns(),
            header.collector_version, header.config_hash, strategy.name,
            budget_bytes, journal_bytes,
            AnchorInfo(anchor_endpoint, public_key_fingerprint(anchor_public_key)),
        )
        root.mkdir(parents=True)
        write_manifest(root / "manifest.json", self.manifest)
        create_journal(root / "journal.bin", journal_bytes)
        self.store = BudgetedSegmentStore(root, self.manifest)
        self._journal_pending: list[Event] = []
        self._selection_pending: list[Event] = []
        # Live eviction uses a bounded recent prefix. This differs from offline
        # whole-trace scoring; context older than this window is not promoted.
        # Windows VM rate and memory behavior remain unverified.
        self._observed: deque[Event] = deque(maxlen=self.SCORING_HISTORY_EVENTS)
        self._last_sync = 0.0
        self.anchor_outages = 0
        self.last_sync = SyncResult(0, 0, None)
        self.events_seen = 0

    def on_record(self, record: TraceRecord) -> None:
        event = self.normalizer.normalize(record)
        self._journal_pending.append(event)
        self._selection_pending.append(event)
        self._observed.append(event)
        self.events_seen += 1
        if len(self._journal_pending) >= 32:
            self.flush_journal()
        while len(self._selection_pending) >= self.segment_events:
            self._seal_batch(self.segment_events)

    def flush_journal(self) -> None:
        if self._journal_pending:
            append_journal_many(self.root / "journal.bin", self._journal_pending)
            self._journal_pending.clear()

    def on_idle(self) -> None:
        self.flush_journal()
        if self.last_sync.pending_segments and time.monotonic() - self._last_sync >= 5:
            self._sync()

    def _sync(self) -> None:
        self._last_sync = time.monotonic()
        result = sync_receipts(self.root, self.manifest, self.anchor_public_key,
                               self.anchor_auth_key, timeout=self.anchor_timeout)
        self.last_sync = result
        if result.outage is not None:
            self.anchor_outages += 1

    def _seal_batch(self, count: int) -> None:
        self.flush_journal()
        batch = tuple(self._selection_pending[:count])
        allowance = self.manifest.budget_bytes - self.manifest.journal_bytes
        selected = self.strategy.select(batch, allowance)
        if selected.events:
            self.store.eviction_score = self.strategy.eviction_scorer(
                tuple(self._observed))
            self.store.seal(list(selected.events), self.strategy.name, selected.stats,
                            evicted_ts_ns=max(event.ts_ns for event in batch))
            if self.last_sync.outage is None or time.monotonic() - self._last_sync >= 5:
                self._sync()
            else:
                self.last_sync = SyncResult(self.last_sync.anchored_segments,
                                            self.last_sync.pending_segments + 1,
                                            self.last_sync.outage)
        del self._selection_pending[:count]

    def finish(self) -> SyncResult:
        self.flush_journal()
        if self._selection_pending:
            self._seal_batch(len(self._selection_pending))
        self._sync()
        return self.last_sync
