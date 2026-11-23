"""Native fixtures verify effects, never authoring claims alone."""

import hashlib
import importlib
import json
from xml.sax.saxutils import escape

import pytest
from pydantic import ValidationError

START = "2026-01-01T12:00:00Z"
TIME = "2026-01-01T12:01:00Z"
END = "2026-01-01T12:10:00Z"
HOST = "FILE-01.office.example"


def api():
    return importlib.import_module("scenar.datasets.audit")


def scenario():
    return {"time_window": {"start": START, "end": END}, "storyline": [{"id": "archive"}]}


def expectation(**overrides):
    doc = {
        "id": "process",
        "authored_event_id": "archive",
        "source": "sysmon",
        "event_id": 1,
        "host": HOST,
        "time": TIME,
        "fields": {
            "Image": r"C:\Windows\archive.exe",
            "CommandLine": "archive data.zip",
            "User": r"OFFICE\operator01",
        },
    }
    doc.update(overrides)
    return api().EffectExpectation.model_validate(doc)


def process(**overrides):
    row = {
        "id": "1",
        "event_id": 1,
        "time": TIME,
        "host": HOST,
        "data": {
            "Image": r"C:\Windows\archive.exe",
            "CommandLine": "archive data.zip",
            "User": r"OFFICE\operator01",
            "ProcessGuid": "{process-a}",
            "ProcessId": "42",
            "LogonId": "0x10",
        },
    }
    row.update(overrides)
    return row


def write_native(tmp_path, rows=None, truth=None):
    rows = [process()] if rows is None else rows
    for source in ("sysmon", "security"):
        path = tmp_path / "data" / HOST / f"windows_event_{source}.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        parts = []
        for row in rows:
            if row.get("source", "sysmon") != source:
                continue
            data = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in row["data"].items())
            parts.append(
                f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{row["event_id"]}</EventID><EventRecordID>{row["id"]}</EventRecordID><Computer>{row["host"]}</Computer><TimeCreated SystemTime="{row["time"]}"/></System><EventData>{data}</EventData></Event>'
            )
        path.write_text("<Events>" + "".join(parts) + "</Events>")
    if truth is None:
        truth = [
            {
                "record_id": "archive#0",
                "storyline_id": "archive",
                "kind": "process",
                "system": "FILE-01",
                "actor": "operator01",
                "time": TIME,
                "emitted": True,
                "attributes": {
                    "pid": 42,
                    "process_name": r"C:\Windows\archive.exe",
                    "command_line": "archive data.zip",
                },
            }
        ]
    (tmp_path / "GROUND_TRUTH.json").write_text(
        json.dumps({"collection_window": {"start": START, "end": END}, "events": truth})
    )
    return tmp_path


def file_expectation():
    return expectation(
        id="file",
        event_id=11,
        fields={"TargetFilename": r"C:\data.zip"},
        relationship={
            "expectation_id": "process",
            "field": "ProcessGuid",
            "target_field": "ProcessGuid",
            "kind": "process_guid",
        },
    )


def file_row(guid="{process-a}", **overrides):
    return process(
        id="2",
        event_id=11,
        data={"TargetFilename": r"C:\data.zip", "ProcessGuid": guid},
        **overrides,
    )


def test_actual_process_has_native_locator_hash_and_private_scope(tmp_path):
    native = write_native(tmp_path)
    report = api().audit_native(native, scenario(), [expectation()])
    assert report.passed
    effect = report.effects[0]
    assert effect.status == "observed"
    assert effect.evidence_ids == [f"data/{HOST}/windows_event_sysmon.xml#1"]
    path = f"data/{HOST}/windows_event_sysmon.xml"
    assert report.source_hashes[path] == hashlib.sha256((native / path).read_bytes()).hexdigest()
    assert report.scope == "authored_expectations_only"
    assert report.ambient_labels == "unknown"
    assert api().AuditReport.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize(
    "rows,status", [([], "missing"), ([process(), process(id="2")], "ambiguous")]
)
def test_native_omission_and_duplicate_matches_fail(tmp_path, rows, status):
    report = api().audit_native(write_native(tmp_path, rows), scenario(), [expectation()])
    assert not report.passed
    assert report.effects[0].status == status


def test_effect_requires_exact_process_guid_not_archive_command(tmp_path):
    report = api().audit_native(
        write_native(tmp_path, [process(), file_row("{decoy}")]),
        scenario(),
        [file_expectation(), expectation()],
    )
    assert not report.passed
    assert {e.expectation_id: e.status for e in report.effects} == {
        "process": "observed",
        "file": "missing",
    }
    report = api().audit_native(
        write_native(tmp_path, [file_row(), process()]),
        scenario(),
        [file_expectation(), expectation()],
    )
    assert report.passed


@pytest.mark.parametrize(
    "change",
    [
        {"time": "2026-01-01T12:11:00Z"},
        {"host": "decoy.office.example"},
        {"data": {**process()["data"], "ProcessId": "99"}},
    ],
)
def test_wrong_host_future_and_pid_decoys_do_not_match(tmp_path, change):
    report = api().audit_native(
        write_native(tmp_path, [process(**change)]), scenario(), [expectation()]
    )
    assert not report.passed
    assert report.effects[0].status == "missing"


def test_duplicate_native_and_authored_ids_fail_closed(tmp_path):
    report = api().audit_native(
        write_native(tmp_path, [process(), process()]), scenario(), [expectation()]
    )
    assert not report.passed
    assert any("Duplicate native" in e for e in report.errors)
    truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())["events"]
    report = api().audit_native(
        write_native(tmp_path, truth=truth * 2), scenario(), [expectation()]
    )
    assert not report.passed
    assert any("Duplicate truth" in e for e in report.errors)
    with pytest.raises(ValueError, match="Duplicate expectation"):
        api().audit_native(tmp_path, scenario(), [expectation(), expectation()])


def test_truth_order_does_not_define_authored_mapping(tmp_path):
    write_native(tmp_path)
    truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())["events"]
    other = {**truth[0], "record_id": "other#0", "storyline_id": "other"}
    a = api().audit_native(
        write_native(tmp_path, truth=[other, *truth]), scenario(), [expectation()]
    )
    b = api().audit_native(
        write_native(tmp_path, truth=[*truth, other]), scenario(), [expectation()]
    )
    assert a.passed and b.passed
    assert a.effects == b.effects


def test_unknown_effect_unsupported_and_no_vacuous_pass(tmp_path):
    write_native(tmp_path)
    report = api().audit_native(tmp_path, scenario(), [expectation(event_id=999)])
    assert report.effects[0].status == "unsupported"
    assert not report.passed
    assert not api().audit_native(tmp_path, scenario(), []).passed


def test_strict_contract_rejects_coercions_and_weak_process_signature():
    for changes in (
        {"tolerance_seconds": True},
        {"event_id": True},
        {"time": "2026-01-01"},
        {"fields": {"CommandLine": "archive data.zip"}},
        {"unexpected": 1},
    ):
        with pytest.raises(ValidationError):
            expectation(**changes)


def test_logon_join_normalizes_hex_but_rejects_zero_and_future_session(tmp_path):
    logon = process(
        id="9",
        source="security",
        event_id=4624,
        data={
            "TargetUserName": "operator01",
            "TargetDomainName": "OFFICE",
            "LogonType": "10",
            "IpAddress": "10.0.0.2",
            "TargetLogonId": "16",
        },
    )
    write_native(tmp_path)
    truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())["events"]
    truth.append(
        {
            **truth[0],
            "record_id": "session#0",
            "storyline_id": "session",
            "kind": "rdp_session",
            "attributes": {},
        }
    )
    session = expectation(
        id="session",
        authored_event_id="session",
        source="security",
        event_id=4624,
        fields={k: v for k, v in logon["data"].items() if k != "TargetLogonId"},
    )
    proc = expectation(
        relationship={
            "expectation_id": "session",
            "field": "LogonId",
            "target_field": "TargetLogonId",
            "kind": "logon_id",
        }
    )
    assert (
        api()
        .audit_native(
            write_native(tmp_path, [process(), logon], truth), scenario(), [proc, session]
        )
        .passed
    )
    for data in (
        {**logon, "time": "2026-01-01T12:01:01Z"},
        {**logon, "data": {**logon["data"], "TargetLogonId": "0"}},
    ):
        assert (
            not api()
            .audit_native(
                write_native(tmp_path, [process(), data], truth), scenario(), [proc, session]
            )
            .passed
        )


def test_zeek_json_lines_are_source_backed_and_preserve_uid(tmp_path):
    write_native(tmp_path)
    path = tmp_path / "data" / "core-span" / "conn.json"
    path.parent.mkdir()
    row = {
        "ts": 1767268860.0,
        "uid": "Cnative",
        "id.orig_h": "10.0.0.2",
        "id.resp_h": "203.0.113.2",
        "id.resp_p": 443,
        "proto": "tcp",
    }
    path.write_text(json.dumps(row) + "\n")
    exp = expectation(
        id="flow",
        source="zeek",
        event_id="conn",
        host="core-span",
        fields={k: str(v) for k, v in row.items() if k not in {"ts", "uid"}},
    )
    report = api().audit_native(tmp_path, scenario(), [exp])
    assert report.passed
    assert report.effects[0].evidence_ids == ["data/core-span/conn.json#Cnative"]
    path.write_text(json.dumps({**row, "ts": 1767268866.0}) + "\n")
    assert not api().audit_native(tmp_path, scenario(), [exp]).passed


@pytest.mark.parametrize(
    "event_id,fields,relation_field",
    [
        (13, {"TargetObject": r"HKCU\Run\update", "Details": "update.exe"}, "ProcessGuid"),
        (
            10,
            {"TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1fffff"},
            "SourceProcessGUID",
        ),
        (
            3,
            {"DestinationIp": "203.0.113.2", "DestinationPort": "443", "Protocol": "tcp"},
            "ProcessGuid",
        ),
    ],
)
def test_registry_credential_and_network_effects_require_native_rows(
    tmp_path, event_id, fields, relation_field
):
    exp = expectation(
        id="effect",
        event_id=event_id,
        fields=fields,
        relationship={
            "expectation_id": "process",
            "field": relation_field,
            "target_field": "ProcessGuid",
            "kind": "process_guid",
        },
    )
    report = api().audit_native(write_native(tmp_path), scenario(), [exp, expectation()])
    assert not report.passed
    row = process(id="3", event_id=event_id, data={**fields, relation_field: "{process-a}"})
    assert (
        api()
        .audit_native(write_native(tmp_path, [process(), row]), scenario(), [exp, expectation()])
        .passed
    )


@pytest.mark.parametrize(
    "event_id,fields",
    [
        (4697, {"ServiceName": "inventory", "ServiceFileName": r"C:\Windows\inventory.exe"}),
        (4698, {"TaskName": r"\Office\Inventory", "SubjectUserName": "operator01"}),
    ],
)
def test_task_and_service_effects_require_native_security_records(tmp_path, event_id, fields):
    exp = expectation(id="persistence", source="security", event_id=event_id, fields=fields)
    assert not api().audit_native(write_native(tmp_path), scenario(), [exp]).passed
    row = process(id="77", source="security", event_id=event_id, data=fields)
    assert api().audit_native(write_native(tmp_path, [row]), scenario(), [exp]).passed


def test_malformed_xml_and_truth_return_failed_report(tmp_path):
    write_native(tmp_path)
    path = tmp_path / "data" / HOST / "windows_event_sysmon.xml"
    path.write_text("<Events><Event></broken>")
    report = api().audit_native(tmp_path, scenario(), [expectation()])
    assert not report.passed and report.errors
    write_native(tmp_path)
    data = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())
    data["events"][0]["time"] = "invalid"
    (tmp_path / "GROUND_TRUTH.json").write_text(json.dumps(data))
    report = api().audit_native(tmp_path, scenario(), [expectation()])
    assert not report.passed and report.errors


def test_truth_host_cannot_bind_same_pid_on_another_system(tmp_path):
    write_native(tmp_path)
    data = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())
    data["events"][0]["system"] = "OTHER"
    (tmp_path / "GROUND_TRUTH.json").write_text(json.dumps(data))
    assert not api().audit_native(tmp_path, scenario(), [expectation()]).passed


def test_schema_version_boolean_is_not_version_one():
    with pytest.raises(ValidationError):
        expectation(schema_version=True)


def test_native_window_must_agree_with_frozen_scenario(tmp_path):
    native = write_native(tmp_path)
    changed = scenario()
    changed["time_window"]["end"] = "2026-01-01T12:00:30Z"
    report = api().audit_native(native, changed, [expectation()])
    assert not report.passed and report.errors


def test_relationship_cannot_cross_host_or_reference_missing_id(tmp_path):
    native = write_native(tmp_path, [process(), file_row(host="OTHER.office.example")])
    assert not api().audit_native(native, scenario(), [expectation(), file_expectation()]).passed
    with pytest.raises(ValueError, match="unknown expectation"):
        api().audit_native(native, scenario(), [file_expectation()])


def test_zeek_tsv_dns_adapter_preserves_query_and_source_identity(tmp_path):
    native = write_native(tmp_path)
    path = native / "data" / "core-span" / "dns.log"
    path.parent.mkdir()
    path.write_text(
        "#separator \\x09\n#fields\tts\tuid\ttrans_id\tid.orig_h\tid.resp_h\tquery\n1767268860.0\tCquery\t1\t10.0.0.2\t10.0.0.1\tupdates.example\n"
    )
    exp = expectation(
        id="dns",
        source="zeek",
        event_id="dns",
        host="core-span",
        fields={"id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1", "query": "updates.example"},
    )
    report = api().audit_native(native, scenario(), [exp])
    assert report.passed
    assert report.effects[0].evidence[0].native_record_id == "Cquery:1:1767268860.0"


def test_scenario_duration_and_warmup_use_collection_start(tmp_path):
    doc = {"time_window": {"start": START, "duration": "10m", "warmup": "1h"}}
    assert api().audit_native(write_native(tmp_path), doc, [expectation()]).passed


def test_authored_intent_ledger_overrides_sorted_truth_ordinals(tmp_path):
    write_native(tmp_path)
    truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())
    original = truth["events"][0]
    truth["events"] = [
        {**original, "record_id": "archive#1", "intent_id": "wanted"},
        {
            **original,
            "record_id": "archive#0",
            "intent_id": "other",
            "attributes": {**original["attributes"], "pid": 999},
        },
    ]
    truth["intent_reconciliation"] = {
        "intents": [
            {"storyline_id": "archive", "intent_id": "wanted"},
            {"storyline_id": "archive", "intent_id": "other"},
        ]
    }
    (tmp_path / "GROUND_TRUTH.json").write_text(json.dumps(truth))
    report = api().audit_native(tmp_path, scenario(), [expectation(authored_event_id="archive#0")])
    assert report.passed
    assert report.effects[0].truth_record_ids == ["archive#1"]


def test_beacon_ticks_anchor_to_actual_truth_and_require_each_native_flow(tmp_path):
    write_native(tmp_path)
    data = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())
    data["events"] = [{**data["events"][0], "kind": "beacon", "time": "2026-01-01T12:00:57Z"}]
    (tmp_path / "GROUND_TRUTH.json").write_text(json.dumps(data))
    doc = scenario()
    doc["storyline"] = [
        {
            "id": "archive",
            "time": "+60s",
            "events": [{"type": "beacon", "count": 3, "interval": "2s", "jitter": 0}],
        }
    ]
    path = tmp_path / "data" / "core-span" / "conn.json"
    path.parent.mkdir()
    fields = {
        "id.orig_h": "10.0.0.2",
        "id.resp_h": "203.0.113.2",
        "id.resp_p": "443",
        "proto": "tcp",
    }
    rows = [{**fields, "ts": 1767268857 + tick * 2, "uid": f"C{tick}"} for tick in range(3)]
    path.write_text("\n".join(json.dumps(r) for r in rows))
    exps = [
        expectation(
            id=f"tick{tick}",
            authored_event_id="archive#0",
            source="zeek",
            event_id="conn",
            host="core-span",
            fields=fields,
            time=f"2026-01-01T12:01:0{tick * 2}Z",
            tolerance_seconds=35,
        )
        for tick in range(3)
    ]
    report = api().audit_native(tmp_path, doc, exps)
    assert report.passed
    assert [e.evidence_ids for e in report.effects] == [
        [f"data/core-span/conn.json#C{tick}"] for tick in range(3)
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows[:2]))
    report = api().audit_native(tmp_path, doc, exps)
    assert not report.passed
    assert report.effects[-1].status == "missing"


def test_bare_step_cannot_hide_multiple_authored_intents(tmp_path):
    write_native(tmp_path)
    data = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())
    data["events"].append(
        {**data["events"][0], "record_id": "archive#1", "attributes": {"pid": 99}}
    )
    (tmp_path / "GROUND_TRUTH.json").write_text(json.dumps(data))
    report = api().audit_native(tmp_path, scenario(), [expectation()])
    assert not report.passed
    assert report.effects[0].status == "ambiguous"


def test_distinct_expectations_cannot_reuse_one_observation(tmp_path):
    report = api().audit_native(
        write_native(tmp_path), scenario(), [expectation(), expectation(id="second-process")]
    )
    assert not report.passed
    assert any("reused" in error for error in report.errors)


def test_symlink_native_root_is_rejected(tmp_path):
    native = write_native(tmp_path / "capture")
    link = tmp_path / "linked"
    link.symlink_to(native, target_is_directory=True)
    report = api().audit_native(link, scenario(), [expectation()])
    assert not report.passed
    assert any("symlink" in error for error in report.errors)


@pytest.mark.parametrize(
    "event_id,fields",
    [
        (4697, {"ServiceName": "inventory", "ServiceFileName": r"C:\inventory.exe"}),
        (4698, {"TaskName": r"\Office\Inventory"}),
    ],
)
def test_persistence_record_from_another_account_is_not_the_authored_effect(
    tmp_path, event_id, fields
):
    fields = {**fields, "SubjectUserName": "operator01", "SubjectDomainName": "OFFICE"}
    exp = expectation(id="persistence", source="security", event_id=event_id, fields=fields)
    decoy = process(
        source="security", event_id=event_id, data={**fields, "SubjectUserName": "otheruser"}
    )
    report = api().audit_native(write_native(tmp_path, [decoy]), scenario(), [exp])
    assert not report.passed
    assert report.effects[0].status == "missing"
