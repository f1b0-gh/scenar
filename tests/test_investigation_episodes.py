"""Private labels must not alter public decisions; scopes, budgets and grading are real."""

from copy import deepcopy

import pytest

from scenar.evaluation import bench, models, native


def record(key, command, minute=7, parent="parent", host="fs.example", guid=None):
    return {
        "id": key,
        "source": "sysmon",
        "event_id": 1,
        "host": host,
        "time": f"2024-05-27T12:{minute:02d}:00Z",
        "data": {
            "CommandLine": command,
            "ProcessGuid": guid or key,
            "ParentProcessGuid": parent,
            "ProcessId": str(minute),
            "User": "EXAMPLE\\admin",
            "LogonId": "0x123",
            "Image": "cmd.exe" if command.startswith("cmd") else "powershell.exe",
        },
    }


def fixture():
    rows = [
        record("p", "cmd.exe /k", 6, guid="parent"),
        record("d", r"cmd.exe /c dir C:\Data /s"),
        record(
            "a",
            r"powershell.exe -NoProfile -Command Compress-Archive -Path C:\Data -DestinationPath C:\Temp\out.zip -Force",
            9,
        ),
    ]
    rows.append(
        {
            "id": "f",
            "source": "sysmon",
            "event_id": 11,
            "host": "fs.example",
            "time": "2024-05-27T12:09:01Z",
            "data": {"ProcessGuid": "a", "TargetFilename": r"C:\Temp\out.zip"},
        }
    )
    approval = {
        "id": "chg",
        "revision": 1,
        "available_at": "2024-05-26T00:00:00Z",
        "valid_from": "2024-05-27T12:00:00Z",
        "valid_until": "2024-05-27T12:15:00Z",
        "account": "EXAMPLE\\admin",
        "hosts": ["fs.example"],
        "grants": [
            {"action": "inventory", "input_path": r"C:\Data"},
            {"action": "archive", "input_path": r"C:\Data", "output_path": r"C:\Temp\out.zip"},
        ],
    }
    return {
        "start": "2024-05-27T12:00:00Z",
        "as_of": "2024-05-27T12:15:00Z",
        "records": rows,
        "approvals": [approval],
    }


def run(value, policy="context", budget=64):
    return bench.investigate(models.Snapshot.model_validate(value), policy, budget)


def test_scoped_grant_cannot_authorize_different_output():
    value = fixture()
    assert set(run(value).decisions.values()) == {"clear"}
    value["approvals"][0]["grants"][1]["output_path"] = r"C:\Temp\other.zip"
    assert run(value).decisions == {"d": "clear", "a": "escalate"}


def test_future_and_revoked_permissions_do_not_leak():
    value = fixture()
    value["approvals"][0]["available_at"] = "2024-05-27T12:16:00Z"
    assert set(run(value).decisions.values()) == {"escalate"}
    value = fixture()
    revoke = deepcopy(value["approvals"][0])
    revoke.update(revision=2, grants=[], available_at="2024-05-27T12:10:00Z")
    value["approvals"].append(revoke)
    assert set(run(value).decisions.values()) == {"escalate"}


def test_budget_exhaustion_and_absent_history_are_unresolved():
    value = fixture()
    value["approvals"] = []
    out = run(value, budget=0)
    assert out.queries == 0 and set(out.decisions.values()) == {"unresolved"}
    value["records"] = value["records"][1:]
    assert set(run(value).decisions.values()) == {"unresolved"}
    assert run(fixture(), budget=1).queries == 1


def test_private_episode_partitions_do_not_change_public_candidates():
    value = fixture()
    value["approvals"] = []
    output = run(value, "unique_chain")
    one = models.Oracle(episodes={"e": "actionable"}, actions={"d": ["e"], "a": ["e"]})
    two = models.Oracle(
        episodes={"e": "actionable", "f": "actionable"}, actions={"d": ["e"], "a": ["f"]}
    )
    assert output.groups == [["a", "d"]]
    assert bench.grade(output, one)["false_fusion_pairs"] == 0
    assert bench.grade(output, two)["false_fusion_pairs"] == 1
    assert bench.grade(run(value, "context"), one)["duplicate_escalations"] == 1


def test_unknown_and_shared_context_are_not_false_positive_labels():
    output = run(fixture(), "alert_only")
    oracle = models.Oracle(episodes={"e": "actionable"}, actions={"d": ["e"], "a": []})
    grade = bench.grade(output, oracle)
    assert grade["unknown_candidates"] == 1
    assert grade["false_escalations"] == 0
    assert grade["actionable_episodes"] == 1


def test_duplicate_native_ids_and_unknown_private_episode_are_rejected():
    value = fixture()
    value["records"].append(value["records"][0])
    with pytest.raises(ValueError):
        run(value)
    with pytest.raises(ValueError):
        models.Oracle(episodes={}, actions={"d": ["missing"]})


def test_native_match_is_exact_and_skips_cannot_match_background():
    row = fixture()["records"][1]
    event = {
        "record_id": "step#0",
        "intent_id": "i",
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
    assert native.match_process(event, [models.Record.model_validate(row)]).id == "d"
    event["emitted"] = False
    with pytest.raises(ValueError, match="emitted"):
        native.match_process(event, [models.Record.model_validate(row)])
    event["emitted"] = True
    other = deepcopy(row)
    other["id"] = "duplicate"
    with pytest.raises(ValueError, match="ambiguous"):
        native.match_process(event, [models.Record.model_validate(r) for r in (row, other)])


def test_future_file_is_not_pivot_evidence():
    value = fixture()
    value["approvals"] = []
    value["records"][-1]["time"] = "2024-05-27T12:16:00Z"
    assert set(run(value).decisions.values()) == {"unresolved"}


def test_irrelevant_files_cannot_exhaust_targeted_lineage_reply():
    value = fixture()
    value["approvals"] = []
    for i in range(40):
        unrelated = deepcopy(value["records"][-1])
        unrelated.update(id=f"noise-{i}", time="2024-05-27T12:01:00Z")
        unrelated["data"] = {"ProcessGuid": "other", "TargetFilename": rf"C:\Temp\{i}.zip"}
        value["records"].append(unrelated)
    assert set(run(value).decisions.values()) == {"escalate"}


def test_partially_unknown_membership_cannot_be_adjudicated_benign():
    output = run(fixture(), "alert_only")
    oracle = models.Oracle(
        episodes={"b": "benign", "u": "unknown"}, actions={"d": ["b", "u"], "a": ["b", "u"]}
    )
    result = bench.grade(output, oracle)
    assert result["false_escalations"] == 0
    assert result["unknown_candidates"] == 2


def test_private_reconciliation_ignores_context_membership_for_scoring():
    row = fixture()["records"][1]
    row["id"] = "data/fs/sysmon.xml#1"
    event = {
        "record_id": "step#0",
        "intent_id": "i",
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
    contract = models.Contract(
        episodes={"e": "actionable"},
        members=[{"authored_record_id": "step#0", "episode_ids": ["e"], "role": "context"}],
    )
    oracle, index = native.reconcile(
        {"events": [event]},
        [models.Record.model_validate(row)],
        contract,
        {"data/fs/sysmon.xml": "a" * 64},
    )
    assert oracle.actions == {}
    assert index[0]["native_record_id"] == "1"
    assert index[0]["intent_id"] == "i"
