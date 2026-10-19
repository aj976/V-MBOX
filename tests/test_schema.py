import json
import re
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid5

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vmbox.canonical import canonical_json
from vmbox.schema import (
    Checkpoint,
    EvaluationResult,
    Event,
    GroundTruthLabel,
    Receipt,
    Reconstruction,
    SessionManifest,
    Tombstone,
)

SCHEMA = Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md"
EXAMPLE_TYPES = [Event, SessionManifest, Tombstone, Checkpoint, Receipt,
                 Reconstruction, GroundTruthLabel, EvaluationResult]


def examples():
    text = SCHEMA.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\s*(.*?)```", text, flags=re.DOTALL)
    assert len(blocks) == len(EXAMPLE_TYPES)
    return [json.loads(block) for block in blocks]


def test_schema_examples_load_and_validate():
    for model_type, data in zip(EXAMPLE_TYPES, examples(), strict=True):
        model = model_type.from_dict(data)
        assert json.loads(model.to_json()) == data


def test_result_requires_every_provenance_field():
    result = examples()[-1]
    required = ["trace_hash", "label_hash", "config_hash", "git_commit", "git_dirty",
                "strategy_rules_version", "tool_versions"]
    for field in required:
        incomplete = result.copy()
        del incomplete[field]
        with pytest.raises(ValueError):
            EvaluationResult.from_dict(incomplete)
    for field in ["python", "vmbox", "lockfile_hash", "windows_build", "sysmon_version",
                  "etw_pywintrace"]:
        incomplete = json.loads(json.dumps(result))
        del incomplete["tool_versions"][field]
        with pytest.raises(ValueError):
            EvaluationResult.from_dict(incomplete)


def test_null_metrics_mean_unmeasured():
    result = EvaluationResult.from_dict(examples()[-1])
    assert result.metrics.evidence_coverage is None
    assert result.metrics.persistence_latency_ms.p95 is None


def test_canonical_output_is_byte_identical_across_processes():
    obj = {"é": [1, 2], "ts_ns": 1760000000123456789, "a": None}
    expected = canonical_json(obj)
    code = (
        "from vmbox.canonical import canonical_json; "
        "print(canonical_json({'ts_ns': 1760000000123456789, "
        "'é': [1, 2], 'a': None}).hex())"
    )
    for _ in range(2):
        actual = subprocess.check_output([sys.executable, "-c", code], text=True).strip()
        assert bytes.fromhex(actual) == expected


@given(seq=st.integers(min_value=0, max_value=2**63 - 1),
       ts_ns=st.integers(min_value=0, max_value=2**63 - 1),
       tags=st.lists(st.text(max_size=12), max_size=5))
def test_event_round_trip(seq, ts_ns, tags):
    data = examples()[0]
    data.update(seq=seq, ts_ns=ts_ns, tags=tags,
                event_id=str(uuid5(UUID(data["session_id"]), str(seq))))
    model = Event.from_dict(data)
    assert Event.from_dict(json.loads(model.to_json())) == model


@given(index=st.integers(min_value=0, max_value=2**31 - 1),
       seq_end=st.integers(min_value=0, max_value=2**63 - 1))
def test_checkpoint_round_trip(index, seq_end):
    data = examples()[3]
    data.update(segment_index=index, seq_end=seq_end)
    model = Checkpoint.from_dict(data)
    assert Checkpoint.from_dict(json.loads(model.to_json())) == model


def test_canonical_rejects_nonfinite_float():
    with pytest.raises(ValueError):
        canonical_json({"value": float("nan")})


def test_event_nullable_fields_require_partial_or_meta():
    data = examples()[0]
    for field in ("pid", "ppid", "process"):
        changed = json.loads(json.dumps(data))
        changed[field] = None
        with pytest.raises(ValueError):
            Event.from_dict(changed)
        changed["capture"]["status"] = "partial"
        Event.from_dict(changed)
    changed = json.loads(json.dumps(data))
    changed["process"]["cmdline_hash"] = None
    with pytest.raises(ValueError):
        Event.from_dict(changed)
    changed["capture"]["status"] = "partial"
    Event.from_dict(changed)
    meta = json.loads(json.dumps(data))
    meta.update(event_type="CAPTURE_GAP", category="meta", pid=None, ppid=None, process=None)
    Event.from_dict(meta)


def test_event_id_must_match_session_and_sequence():
    data = examples()[0]
    data["event_id"] = "00000000-0000-5000-8000-000000000000"
    with pytest.raises(ValueError):
        Event.from_dict(data)
