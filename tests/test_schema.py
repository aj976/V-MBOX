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
from vmbox.eval.aggregate_schema import AggregateResult
from vmbox.schema import (
    Checkpoint,
    EvaluationResult,
    Event,
    Gap,
    GroundTruthLabel,
    Receipt,
    Reconstruction,
    Report,
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


def test_report_schema_example_loads_and_validates():
    text = SCHEMA.read_text(encoding="utf-8")
    match = re.search(r"Synthetic format example, not a real evidence report:\s*"
                      r"```text\s*(.*?)```", text, re.DOTALL)
    assert match is not None
    data = json.loads(match.group(1))
    assert Report.from_dict(data).to_dict() == data


def test_aggregate_schema_example_loads_and_validates():
    text = SCHEMA.read_text(encoding="utf-8")
    match = re.search(r"Template, not a measurement \(synthetic failed-attempt shape\):\s*"
                      r"```text\s*(.*?)```", text, re.DOTALL)
    assert match is not None
    data = json.loads(match.group(1))
    assert AggregateResult.from_dict(data).to_dict() == data


def test_gap_null_rules_and_closed_reason():
    example = examples()[5]["gaps"][0]
    with pytest.raises(ValueError, match="require both ranges"):
        Gap.from_dict({**example, "seq_range": None})
    torn = examples()[5]["gaps"][3]
    assert Gap.from_dict(torn).seq_range is None
    with pytest.raises(ValueError):
        Gap.from_dict({**torn, "reason": "maybe something happened"})
    with pytest.raises(ValueError, match="limitation"):
        Reconstruction.from_dict({**examples()[5], "limitations": []})


def test_manifest_mode_anchor_rules():
    live = examples()[1]
    assert SessionManifest.from_dict(live).mode == "live"
    text = SCHEMA.read_text(encoding="utf-8")
    offline_example = json.loads(re.search(
        r"Offline evaluation example:\s*```text\s*(.*?)```", text, re.DOTALL
    ).group(1))
    assert SessionManifest.from_dict(offline_example).mode == "offline_eval"
    with pytest.raises(ValueError):
        SessionManifest.from_dict({**live, "anchor": None})
    with pytest.raises(ValueError):
        SessionManifest.from_dict({**live, "anchor": {
            "endpoint": "", "pubkey_fingerprint": "sha256:..."
        }})
    with pytest.raises(ValueError):
        SessionManifest.from_dict({key: value for key, value in live.items() if key != "mode"})
    offline = {**live, "mode": "offline_eval", "anchor": None}
    assert SessionManifest.from_dict(offline).anchor is None
    assert SessionManifest.from_dict({**offline, "anchor": live["anchor"]}).anchor is not None
    with pytest.raises(ValueError):
        SessionManifest.from_dict({**live, "mode": "unknown"})


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


def test_unbounded_budget_null_round_trip_and_budgeted_validation():
    template = examples()[-1]
    unbounded = EvaluationResult.from_dict(template)
    assert unbounded.budget_bytes is None
    assert unbounded.budget_fraction_of_full is None
    assert unbounded.bytes_retained is None
    assert EvaluationResult.from_dict(json.loads(unbounded.to_json())) == unbounded
    for changes in ({"budget_bytes": 1}, {"budget_fraction_of_full": 0.5}):
        with pytest.raises(ValueError):
            EvaluationResult.from_dict({**template, **changes})
    for changes in ({"budget_bytes": None, "budget_fraction_of_full": 0.5},
                    {"budget_bytes": -1, "budget_fraction_of_full": 0.5},
                    {"budget_bytes": 1, "budget_fraction_of_full": None}):
        with pytest.raises(ValueError):
            EvaluationResult.from_dict({**template, "strategy": "fixed", **changes})
    with pytest.raises(ValueError):
        EvaluationResult.from_dict({**template, "strategy": "typo"})
    budgeted = EvaluationResult.from_dict({**template, "strategy": "fifo_ring",
                                           "budget_bytes": 256,
                                           "budget_fraction_of_full": 0.25,
                                           "bytes_retained": 200})
    assert EvaluationResult.from_dict(json.loads(budgeted.to_json())) == budgeted


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


def test_receipt_rejects_noncanonical_signature_encoding():
    receipt = examples()[4]
    for signature in ("ed25519:" + "A" * 128, "ed25519:" + "0" * 127,
                      "ed25519:" + "g" * 128):
        invalid = {**receipt, "signature": signature}
        with pytest.raises(ValueError):
            Receipt.from_dict(invalid)
