import copy

import pytest
from pydantic import ValidationError

from scenar.background import BackgroundActivity, apply_background
from scenar.truth import GroundTruth, IntentLabel, IntentPredictions, grade_intent


def test_intent_is_independent_of_technique_and_unknown_stays_unknown():
    truth = GroundTruth(
        mode="intent-aware",
        labels={
            "same-technique-benign": IntentLabel(intent="benign", rationale="approved exercise"),
            "same-technique-malicious": IntentLabel(
                intent="malicious", rationale="authored adversary intent"
            ),
        },
    )
    predictions = IntentPredictions(
        decisions={
            "same-technique-benign": "malicious",
            "same-technique-malicious": "malicious",
            "unlabeled": "benign",
        }
    )
    result = grade_intent(truth, predictions)
    assert result["true_positive"] == 1 and result["false_positive"] == 1
    assert result["unknown_truth"] == 1 and result["true_negative"] == 0


def test_behavior_mode_does_not_grade_intent_or_equate_escalation_to_malice():
    assert (
        grade_intent(GroundTruth(), IntentPredictions(decisions={"a": "malicious"}))["enabled"]
        is False
    )
    with pytest.raises(ValidationError):
        IntentPredictions(decisions={"a": "escalate"})
    with pytest.raises(ValidationError):
        IntentLabel(intent=True, rationale="wrong type")
    with pytest.raises(ValidationError):
        IntentLabel(intent="malicious")


def test_intent_abstentions_and_missed_labeled_actions_remain_in_denominator():
    truth = GroundTruth(
        mode="intent-aware",
        labels={
            "a": {"intent": "malicious", "rationale": "authored"},
            "b": {"intent": "benign", "rationale": "authored"},
        },
    )
    result = grade_intent(truth, IntentPredictions(decisions={"a": "abstain"}))
    assert result["unresolved_known"] == 2
    assert result["known_truth"] == 2


def test_background_is_deterministic_and_preserves_focal_actions_and_base():
    scenario = {
        "name": "test",
        "storyline": [{"id": "focus"}],
        "red_herrings": [{"id": "lookalike"}],
        "environment": {"users": []},
        "baseline_activity": {"traffic_affinities": [{"keep": "value"}]},
    }
    original = copy.deepcopy(scenario)
    config = BackgroundActivity(profile="office", intensity="high")
    first = apply_background(scenario, config)
    assert first == apply_background(scenario, config)
    assert scenario == original and first["storyline"] == original["storyline"]
    assert first["baseline_activity"]["intensity"] == "high"
    assert first["baseline_activity"]["traffic_rates"]["user_activity"] == "high"
    assert first["baseline_activity"]["traffic_affinities"] == [{"keep": "value"}]
    only = apply_background(scenario, config, noise_only=True)
    assert only["storyline"] == [] and only["red_herrings"] == []


@pytest.mark.parametrize(
    "rates", [{"unknown": 1}, {"web": 0}, {"web": True}, {"web": [5, 2]}, {"web": 50001}]
)
def test_noise_rejects_unsupported_or_unsafe_rate_values(rates):
    with pytest.raises(ValidationError):
        BackgroundActivity(traffic_rates=rates)


def test_native_truth_overlay_never_inferrs_intent_from_storyline_or_missing_label():
    from scenar.truth import annotate_native_truth

    raw = {
        "events": [
            {"record_id": "a#0", "emitted": True, "ground_truth_section": "storyline"},
            {"record_id": "b#0", "emitted": False, "ground_truth_section": "storyline"},
            {"record_id": "ambient#0", "emitted": True, "ground_truth_section": "red_herrings"},
        ]
    }
    truth = GroundTruth(
        mode="intent-aware",
        labels={
            "a#0": {"intent": "benign", "rationale": "normal inventory"},
            "b#0": {"intent": "malicious", "rationale": "authored adversary intent"},
        },
    )
    result = annotate_native_truth(raw, truth, authored_counts={"a": 1, "b": 1, "ambient": 1})
    assert [e["is_malicious"] for e in result["events"]] == [False, True, None]
    assert result["events"][1]["emitted"] is False
    assert "is_malicious" not in raw["events"][0]
    assert all(
        e["is_malicious"] is None for e in annotate_native_truth(raw, GroundTruth())["events"]
    )


def test_requested_noise_intensity_changes_effective_profile_rates():
    low = apply_background({"name": "s"}, BackgroundActivity(profile="office", intensity="low"))
    high = apply_background({"name": "s"}, BackgroundActivity(profile="office", intensity="high"))
    assert low["baseline_activity"]["traffic_rates"]["user_activity"] == "low"
    assert high["baseline_activity"]["traffic_rates"]["user_activity"] == "high"


def test_intent_overlay_joins_ledger_identity_not_sorted_native_ordinals():
    from scenar.truth import annotate_native_truth

    truth = GroundTruth(
        mode="intent-aware",
        labels={
            "step#0": {"intent": "malicious", "rationale": "authored process"},
            "step#1": {"intent": "benign", "rationale": "authored DNS"},
        },
    )
    raw = {
        "intent_reconciliation": {
            "intents": [
                {
                    "intent_id": "process-id",
                    "storyline_id": "step",
                    "ground_truth_section": "storyline",
                    "event_type": "process",
                },
                {
                    "intent_id": "dns-id",
                    "storyline_id": "step",
                    "ground_truth_section": "storyline",
                    "event_type": "dns_query",
                },
            ]
        },
        "events": [
            {
                "record_id": "step#0",
                "intent_id": "dns-id",
                "storyline_id": "step",
                "kind": "dns_query",
                "emitted": True,
            },
            {
                "record_id": "step#1",
                "intent_id": "process-id",
                "storyline_id": "step",
                "kind": "process",
                "emitted": False,
            },
        ],
    }
    result = annotate_native_truth(raw, truth)
    assert [e["is_malicious"] for e in result["events"]] == [False, True]
    assert [e["authored_record_id"] for e in result["events"]] == ["step#1", "step#0"]
    raw.pop("intent_reconciliation")
    with pytest.raises(ValueError, match="ambiguous|ledger"):
        annotate_native_truth(raw, truth)


def test_single_rendered_event_does_not_prove_single_authored_event():
    from scenar.truth import annotate_native_truth

    truth = GroundTruth(
        mode="intent-aware",
        labels={
            "s#0": {"intent": "malicious", "rationale": "first authored event"},
            "s#1": {"intent": "benign", "rationale": "second authored event"},
        },
    )
    raw = {"events": [{"record_id": "s#0", "storyline_id": "s", "emitted": True}]}
    with pytest.raises(ValueError, match="ledger|ambiguous|Ambiguous"):
        annotate_native_truth(raw, truth)
