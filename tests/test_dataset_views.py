import importlib
import json
from datetime import datetime

import pytest

from scenar.datasets.visibility import VisibilitySettings
from scenar.io import files
from tests.test_dataset_audit import write_native


def transform(native, settings, cutoff="2026-01-01T12:10:00Z", seed=17):
    scenario = {
        "environment": {
            "systems": [{"hostname": "FILE-01", "os": "Windows Server 2022"}],
            "network": {
                "sensors": [
                    {
                        "name": "sensor-1",
                        "hostname": "sensor-box",
                        "type": "network",
                        "log_formats": ["zeek"],
                    }
                ]
            },
        },
        "output": {
            "logs": [
                {"format": "windows_event_sysmon"},
                {"format": "windows_event_security"},
                {"format": "zeek_conn"},
            ]
        },
    }
    return importlib.import_module("scenar.datasets.views").derive_view(
        native,
        scenario,
        settings,
        seed=seed,
        cutoff=datetime.fromisoformat(cutoff.replace("Z", "+00:00")),
    )


@pytest.mark.parametrize(
    "settings,reason",
    [
        (VisibilitySettings(mode="missing_endpoint", hosts=["FILE-01"]), "disabled"),
        (VisibilitySettings(mode="lossy", probability=1.0, hosts=["FILE-01"]), "lost"),
        (
            VisibilitySettings(mode="delayed", delay_us=600000001, hosts=["FILE-01"]),
            "not_yet_available",
        ),
    ],
)
def test_omissions_have_record_receipts_without_changing_native_bytes(tmp_path, settings, reason):
    native = write_native(tmp_path)
    before = files(native)
    outputs, receipt = transform(native, settings)
    assert files(native) == before
    assert receipt.records[0].reason == reason
    assert receipt.records[0].included is False
    assert b"archive.exe" not in b"".join(outputs.values())
    assert receipt.source_hashes and receipt.output_hashes


def test_delay_uses_exact_microsecond_cutoff_and_does_not_rewrite_event_time(tmp_path):
    native = write_native(tmp_path)
    settings = VisibilitySettings(mode="delayed", delay_us=1, hosts=["FILE-01"])
    early, receipt = transform(native, settings, cutoff="2026-01-01T12:01:00Z")
    late, available = transform(native, settings, cutoff="2026-01-01T12:01:00.000001Z")
    assert not receipt.records[0].included
    assert available.records[0].included
    assert available.records[0].available_at_ns - available.records[0].source_time_ns == 1000
    assert b"archive.exe" not in b"".join(early.values())
    assert b"archive.exe" in b"".join(late.values())
    assert b"2026-01-01T12:01:00Z" in b"".join(late.values())


def test_zeek_json_and_tsv_have_exact_timestamps_and_loss_is_reproducible(tmp_path):
    native = write_native(tmp_path, rows=[])
    sensor = native / "data/sensor-1"
    sensor.mkdir()
    (sensor / "conn.json").write_text('{"ts":1767268860.000001,"uid":"C1","duration":0}\n')
    (sensor / "dns.log").write_text(
        "#separator \\x09\n#fields\tts\tuid\ttrans_id\n1767268860.000001\tC2\t12\n"
    )
    settings = VisibilitySettings(mode="lossy", probability=0.5)
    first = transform(native, settings)
    assert first == transform(native, settings)
    assert all(r.source_time_ns == 1767268860000001000 for r in first[1].records)
    assert len(first[1].records) == 2


def test_malformed_native_record_fails_closed(tmp_path):
    native = write_native(tmp_path)
    path = next(native.rglob("*sysmon.xml"))
    path.write_text(path.read_text().replace("2026-01-01T12:01:00Z", "2026-01-01"))
    with pytest.raises(ValueError, match="timestamp"):
        transform(native, VisibilitySettings())


def test_derived_dataset_qualifies_missing_endpoint_but_checks_export_receipt(
    tmp_path, monkeypatch
):
    from scenar.datasets import matrix
    from scenar.storage import export_public, publish_bundle
    from tests.test_datasets import observed_dataset, reseal

    original = matrix.DatasetSpec

    def derived_spec(**kwargs):
        return original(
            **kwargs,
            visibility_application="derived",
            visibility=[VisibilitySettings(mode="missing_endpoint", hosts=["FILE-01"])],
        )

    monkeypatch.setattr("tests.test_datasets.DatasetSpec", derived_spec)
    run, plan, report = observed_dataset(tmp_path, monkeypatch)
    assert report["qualified"] == 2
    publish_bundle(run, str(tmp_path / "store"))
    export_public(run, tmp_path / "export")
    assert b"archive.exe" not in b"".join(
        p.read_bytes() for p in (tmp_path / "export").rglob("*.xml")
    )
    receipt = run / "reports/visibility" / f"{plan.cases[0].id}.json"
    data = json.loads(receipt.read_bytes())
    data["records"][0]["included"] = True
    receipt.write_text(json.dumps(data))
    reseal(run)
    with pytest.raises(ValueError, match="visibility"):
        publish_bundle(run, str(tmp_path / "bad-store"))


def test_connection_summary_is_withheld_until_flow_completes(tmp_path):
    native = write_native(tmp_path, rows=[])
    sensor = native / "data/sensor-1"
    sensor.mkdir()
    (sensor / "conn.json").write_text('{"ts":1767268860.000001,"uid":"C1","duration":60.000001}\n')
    outputs, receipt = transform(native, VisibilitySettings(), cutoff="2026-01-01T12:02:00.000001Z")
    assert not receipt.records[0].included
    assert receipt.records[0].available_at_ns == 1767268920000002000
    assert b"C1" not in b"".join(outputs.values())


def test_backend_seven_digit_timestamp_preserves_exact_native_ticks(tmp_path):
    native = write_native(tmp_path)
    path = next(native.rglob("*sysmon.xml"))
    path.write_text(
        path.read_text().replace("2026-01-01T12:01:00Z", "2026-01-01T12:01:00.0000010Z")
    )
    outputs, receipt = transform(native, VisibilitySettings())
    assert receipt.records[0].source_time_ns == 1767268860000001000
    assert b"2026-01-01T12:01:00.0000010Z" in b"".join(outputs.values())
    path.write_text(path.read_text().replace(".0000010Z", ".0000011Z"))
    _, receipt = transform(native, VisibilitySettings())
    assert receipt.records[0].source_time_ns == 1767268860000001100
    _, early = transform(native, VisibilitySettings(), cutoff="2026-01-01T12:01:00.000001Z")
    assert not early.records[0].included


def test_dns_answer_waits_for_response_time_and_requires_known_rtt(tmp_path):
    native = write_native(tmp_path, rows=[])
    sensor = native / "data/sensor-1"
    sensor.mkdir()
    path = sensor / "dns.json"
    path.write_text('{"ts":1767268860,"uid":"C1","trans_id":12,"rtt":60,"answers":["192.0.2.1"]}\n')
    outputs, receipt = transform(native, VisibilitySettings(), cutoff="2026-01-01T12:01:01Z")
    assert not receipt.records[0].included
    assert receipt.records[0].available_at_ns == 1767268920000000000
    assert b"192.0.2.1" not in b"".join(outputs.values())
    path.write_text(path.read_text().replace('"rtt":60', '"rtt":"-"'))
    outputs, receipt = transform(native, VisibilitySettings())
    assert receipt.records[0].reason == "availability_unknown"
    assert receipt.records[0].available_at_ns is None
    assert b"192.0.2.1" not in b"".join(outputs.values())


def test_unresolved_connection_availability_stays_unknown_and_private(tmp_path):
    native = write_native(tmp_path, rows=[])
    sensor = native / "data/sensor-1"
    sensor.mkdir()
    (sensor / "conn.json").write_text('{"ts":1767268860,"uid":"C1","conn_state":"S0"}\n')
    outputs, receipt = transform(native, VisibilitySettings())
    assert receipt.records[0].reason == "availability_unknown"
    assert receipt.records[0].available_at_ns is None
    assert not receipt.records[0].included
    assert b"C1" not in b"".join(outputs.values())


@pytest.mark.parametrize(
    "row",
    [
        {"ts": True, "uid": "C1", "duration": 0},
        {"ts": 1767268860, "uid": None, "duration": 0},
        {"ts": 1767268860, "uid": "C1", "duration": True},
        {"ts": 1767268860, "uid": ["C1"], "duration": 0},
    ],
)
def test_malformed_zeek_primitives_are_rejected(tmp_path, row):
    native = write_native(tmp_path, rows=[])
    sensor = native / "data/sensor-1"
    sensor.mkdir()
    (sensor / "conn.json").write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError):
        transform(native, VisibilitySettings())


def test_zeek_sensor_hostname_maps_to_exact_deployed_source_name(tmp_path):
    native = write_native(tmp_path, rows=[])
    sensor = native / "data/sensor-box"
    sensor.mkdir()
    (sensor / "conn.json").write_text('{"ts":1767268860,"uid":"C1","duration":0}\n')
    outputs, receipt = transform(
        native,
        VisibilitySettings(mode="lossy", probability=1.0, source_instances=["zeek:sensor-1"]),
    )
    assert receipt.records[0].source_instance == "zeek:sensor-1"
    assert receipt.records[0].reason == "lost"
    assert b"C1" not in b"".join(outputs.values())


def test_dns_negative_response_with_unknown_rtt_is_withheld(tmp_path):
    native = write_native(tmp_path, rows=[])
    sensor = native / "data/sensor-1"
    sensor.mkdir()
    (sensor / "dns.json").write_text(
        '{"ts":1767268860,"uid":"C1","trans_id":12,"rtt":null,"answers":[],"rcode":3,"rcode_name":"NXDOMAIN"}\n'
    )
    outputs, receipt = transform(native, VisibilitySettings(), cutoff="2026-01-01T12:01:00Z")
    assert receipt.records[0].reason == "availability_unknown"
    assert b"NXDOMAIN" not in b"".join(outputs.values())


def test_visibility_receipt_rejects_integer_inclusion_even_after_rehash(tmp_path, monkeypatch):
    from scenar.datasets import matrix
    from scenar.storage import export_public
    from tests.test_datasets import observed_dataset, reseal

    original = matrix.DatasetSpec
    monkeypatch.setattr(
        "tests.test_datasets.DatasetSpec",
        lambda **kwargs: original(
            **kwargs,
            visibility_application="derived",
            visibility=[VisibilitySettings(mode="missing_endpoint", hosts=["FILE-01"])],
        ),
    )
    run, plan, _ = observed_dataset(tmp_path, monkeypatch)
    path = run / "reports/visibility" / f"{plan.cases[0].id}.json"
    data = json.loads(path.read_bytes())
    data["records"][0]["included"] = 0
    path.write_text(json.dumps(data))
    reseal(run)
    with pytest.raises(ValueError):
        export_public(run, tmp_path / "bad-export")
    assert not (tmp_path / "bad-export").exists()
