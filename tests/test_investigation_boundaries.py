"""Adversarial memberships and ambiguous pivots must not fabricate certainty."""

import json
from copy import deepcopy

import pytest

from scenar.evaluation import bench, models
from tests.test_investigation_episodes import fixture, record, run


def test_known_attack_recall_survives_an_additional_unknown_membership():
    output = run(fixture(), "alert_only")
    oracle = models.Oracle(
        episodes={"attack": "actionable", "unresolved": "unknown"},
        actions={"d": ["attack", "unresolved"], "a": []},
    )
    grade = bench.grade(output, oracle)
    assert grade["recalled_episodes"] == 1
    assert grade["false_escalations"] == 0


def test_false_clear_and_partial_action_loss_remain_visible_despite_episode_recall():
    output = run(fixture(), "alert_only").model_dump(mode="json")
    output["decisions"]["d"] = "clear"
    oracle = models.Oracle(
        episodes={"attack": "actionable"},
        actions={"d": ["attack"], "a": ["attack"], "absent": ["attack"]},
    )
    grade = bench.grade(models.Result.model_validate(output), oracle)
    assert grade["recalled_episodes"] == 1
    assert grade["actionable_actions"] == 3
    assert grade["escalated_actionable_actions"] == 1
    assert grade["missed_actionable_actions"] == 2
    assert grade["false_cleared_actions"] == 1


def test_shared_parent_and_resource_do_not_make_a_unique_incident_chain():
    value = fixture()
    value["approvals"] = []
    d = deepcopy(value["records"][1])
    d["id"] = "d2"
    d["data"]["ProcessGuid"] = "d2"
    a = deepcopy(value["records"][2])
    a["id"] = "a2"
    a["data"]["ProcessGuid"] = "a2"
    a["data"]["CommandLine"] = a["data"]["CommandLine"].replace("out.zip", "out2.zip")
    f = deepcopy(value["records"][3])
    f["id"] = "f2"
    f["data"].update(ProcessGuid="a2", TargetFilename=r"C:\Temp\out2.zip")
    value["records"].extend([d, a, f])
    oracle = models.Oracle(
        episodes={"one": "actionable", "two": "actionable"},
        actions={"d": ["one"], "a": ["one"], "d2": ["two"], "a2": ["two"]},
    )
    assert len(run(value, "unique_chain").groups) == 4
    assert bench.grade(run(value, "entity_fusion"), oracle)["false_fusion_pairs"] == 4


def test_candidate_scan_keeps_unlabelled_background_and_ignores_future_actions():
    value = fixture()
    value["records"].append(record("unknown", r"cmd.exe /c dir C:\Elsewhere /s", 8))
    value["records"].append(record("future", r"cmd.exe /c dir C:\Elsewhere /s", 16))
    output = run(value, "alert_only")
    assert set(output.candidates) == {"d", "a", "unknown"}
    oracle = models.Oracle(episodes={"one": "benign"}, actions={"d": ["one"], "a": ["one"]})
    assert bench.grade(output, oracle)["unknown_candidates"] == 1


def test_private_truth_is_not_a_public_snapshot_field():
    value = fixture()
    value["episodes"] = {"secret": "actionable"}
    with pytest.raises(ValueError):
        models.Snapshot.model_validate(value)


def test_missing_result_candidate_and_excess_queries_are_rejected():
    output = run(fixture()).model_dump(mode="json")
    output["candidates"].pop()
    with pytest.raises(ValueError):
        models.Result.model_validate(output)
    output = run(fixture()).model_dump(mode="json")
    output["budget"] = 0
    with pytest.raises(ValueError):
        models.Result.model_validate(output)


def test_delivered_groups_cannot_award_credit_to_cleared_members():
    output = run(fixture(), "alert_only").model_dump(mode="json")
    output["decisions"]["d"] = "clear"
    output["groups"] = [["d", "a"]]
    with pytest.raises(ValueError, match="escalated"):
        models.Result.model_validate(output)


def test_detector_feed_and_scan_cost_exclude_future_and_unmetered_context():
    value = fixture()
    baseline = run(value, "alert_only")
    value["records"].append(record("future", r"cmd.exe /c dir C:\Future /s", 16))
    value["approvals"][0]["available_at"] = "2024-05-27T12:16:00Z"
    snapshot = models.Snapshot.model_validate(value)
    future = bench.investigate(snapshot, "alert_only", 0)
    assert future.scanned_records == baseline.scanned_records
    assert future.scanned_bytes == baseline.scanned_bytes
    feed = bench.candidate_feed(snapshot)
    assert set(feed) == {"format", "start", "as_of", "candidates"}
    assert {c["record"]["id"] for c in feed["candidates"]} == {"d", "a"}


def test_distinct_authored_context_births_cannot_alias_one_native_record():
    from scenar.evaluation import native

    row = fixture()["records"][1]
    row["id"] = "data/fs/sysmon.xml#1"
    event = {
        "record_id": "first#0",
        "kind": "process",
        "emitted": True,
        "time": row["time"],
        "actor": "admin",
        "system": "fs",
        "attributes": {
            "pid": 7,
            "command_line": row["data"]["CommandLine"],
            "process_name": "cmd.exe",
        },
    }
    other = dict(event, record_id="second#0")
    contract = models.Contract(
        episodes={},
        members=[
            {"authored_record_id": i, "episode_ids": [], "role": "context"}
            for i in ("first#0", "second#0")
        ],
    )
    with pytest.raises(ValueError, match="same observation"):
        native.reconcile(
            {"events": [event, other]},
            [models.Record.model_validate(row)],
            contract,
            {"data/fs/sysmon.xml": "a" * 64},
        )


def test_incomplete_or_duplicate_comparison_matrix_is_failure():
    summary = runner()["summarize"]
    protocol = {
        "cases": [{"id": "x"}],
        "contexts": ["available"],
        "policies": ["context"],
        "budgets": [4],
    }
    attempts = [{"id": "x", "eligible": True}]
    row = {"case": "x", "context": "available", "policy": "context", "budget": 4}
    assert not summary(protocol, attempts, [])["execution_complete"]
    assert not summary(protocol, attempts, [row, row])["execution_complete"]
    assert summary(protocol, attempts, [row])["execution_complete"]
    assert not summary(protocol, [{"id": "x", "eligible": False}], [row])["execution_complete"]


def test_eligibility_artifact_reports_private_audit_failure(tmp_path):
    # A real source/GT mismatch reaches reconciliation after an empty legacy-check list.
    # This tests error reporting, not successful capture qualification.
    bundle = tmp_path / "bundle"
    (bundle / "data").mkdir(parents=True)
    (bundle / "GROUND_TRUTH.json").write_text(json.dumps({"events": []}))
    (tmp_path / "quality.stdout").write_text(
        json.dumps({"acceptance_passed": True, "overall_score": 100, "flags": []})
    )
    case = {
        "approvals": [],
        "audits": [],
        "private": {
            "episodes": {},
            "members": [{"authored_record_id": "missing#0", "episode_ids": [], "role": "context"}],
        },
    }
    protocol = {
        "contexts": ["available"],
        "start": "2024-05-27T12:00:00Z",
        "as_of": "2024-05-27T12:15:00Z",
    }
    with pytest.raises(ValueError, match="authored member"):
        runner()["evaluate_capture"](tmp_path, case, protocol)
    eligibility = json.loads((tmp_path / "eligibility.json").read_text())
    assert eligibility["eligible"] is False
    assert any("authored member" in e for e in eligibility["errors"])


def test_quality_cli_success_is_not_hard_criteria_acceptance(tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "data").mkdir(parents=True)
    (bundle / "GROUND_TRUTH.json").write_text(json.dumps({"events": []}))
    (tmp_path / "quality.stdout").write_text(
        json.dumps(
            {
                "acceptance_passed": False,
                "overall_score": 95,
                "flags": ["[HARD] causality.temporal_integrity: below threshold"],
            }
        )
    )
    case = {
        "id": "case",
        "seed": 1,
        "family": "benign_only",
        "approvals": [],
        "audits": [],
        "private": {"episodes": {}, "members": []},
    }
    protocol = {
        "contexts": ["available"],
        "start": "2024-05-27T12:00:00Z",
        "as_of": "2024-05-27T12:15:00Z",
        "policies": ["alert_only"],
        "budgets": [0],
    }
    rows = runner()["evaluate_capture"](tmp_path, case, protocol)
    eligibility = json.loads((tmp_path / "eligibility.json").read_text())
    assert eligibility["eligible"] is False
    assert eligibility["native_eligible"] is True
    assert rows[0]["diagnostic_only"] is True
    assert eligibility["quality"]["acceptance_passed"] is False


def runner():
    from scenar.evaluation import episodes

    return vars(episodes)
