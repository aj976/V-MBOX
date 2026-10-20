"""M5 scenario definitions are tested without executing VM-only workloads."""

from scenarios.run_m5 import build_labels
from vmbox.schema import GroundTruthLabel


def test_three_families_have_predeclared_anchor_relative_steps():
    for family, expected_types in (
        ("child_chain", ["PROC_START", "PROC_START"]),
        ("query_connect", ["PROC_START", "MEM_PROCESS_ACCESS", "NET_CONNECT"]),
        ("benign_lookalike", ["PROC_START", "NET_CONNECT"]),
    ):
        labels = build_labels(family, 7, "nonce7", "run-7", 0.321)
        assert isinstance(labels, GroundTruthLabel)
        assert labels.anchor.nonce in labels.anchor.image_regex
        assert [step.match.event_type for step in labels.steps] == expected_types
        assert all(step.match.ts_window_ns == [0, 8_000_000_000] for step in labels.steps)
        assert labels.steps[0].match.pid_lineage.step_id == "anchor"
        assert labels.review_resolutions == []
        assert GroundTruthLabel.from_dict(labels.to_dict()) == labels


def test_benign_lookalike_has_no_attack_relevant_steps():
    labels = build_labels("benign_lookalike", 2, "nonce2", "run-2", 0.4)
    assert all(step.relevance == "benign" for step in labels.steps)
