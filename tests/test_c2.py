import pytest

from scenar.evaluation import c2 as chain


def test_owner_link_rejects_shared_host_without_parent_guid():
    parent = chain.Record(
        id="p",
        source="sysmon",
        event_id=1,
        host="h",
        time="2024-07-15T12:05:00Z",
        data={"ProcessGuid": "gp", "User": "a", "LogonId": "0x22"},
    )
    child = chain.Record(
        id="c",
        source="sysmon",
        event_id=1,
        host="h",
        time="2024-07-15T12:06:00Z",
        data={"ProcessGuid": "gc", "ParentProcessGuid": "gp", "User": "a", "LogonId": "0x22"},
    )
    assert chain.exact_parent(parent, child)
    for field, val in [("ParentProcessGuid", "other"), ("User", "other"), ("LogonId", "0x23")]:
        bad = child.model_copy(update={"data": {**child.data, field: val}})
        assert not chain.exact_parent(parent, bad)
    assert not chain.exact_parent(parent, child.model_copy(update={"host": "other"}))
    assert not chain.exact_parent(parent, child.model_copy(update={"time": parent.time}))


def test_only_public_envelopes_accepted():
    with pytest.raises(ValueError):
        chain.find_chains(
            {
                "as_of": "2024-07-15T12:25:00Z",
                "records": [],
                "permissions": [],
                "episodes": {"e0": "actionable"},
            },
            "2024-07-15T12:00:00Z",
        )


def test_wire_requires_completed_exact_socket():
    socket = chain.Record(
        id="s",
        source="sysmon",
        event_id=3,
        host="h",
        time="2024-07-15T12:05:00Z",
        data={
            "SourceIp": "10.0.0.1",
            "SourcePort": "12345",
            "DestinationIp": "198.51.100.70",
            "DestinationPort": "443",
            "Protocol": "tcp",
            "ProcessGuid": "gp",
        },
    )
    wire = chain.Record(
        id="w",
        source="zeek_conn",
        event_id=0,
        host="10.0.0.1",
        time=socket.time,
        data={
            "id.orig_h": "10.0.0.1",
            "id.orig_p": "12345",
            "id.resp_h": "198.51.100.70",
            "id.resp_p": "443",
            "proto": "tcp",
            "duration": "2",
            "uid": "u",
        },
    )
    cutoff = chain.stamp("2024-07-15T12:10:00Z")
    assert chain.wire_match(socket, wire, cutoff)
    assert not chain.wire_match(
        socket, wire.model_copy(update={"data": {**wire.data, "id.orig_p": "999"}}), cutoff
    )
    assert not chain.wire_match(socket, wire, chain.stamp("2024-07-15T12:05:01Z"))


def test_terminated_uploader_cannot_own_later_contacts():
    birth = chain.Record(
        id="p",
        source="sysmon",
        event_id=1,
        host="h",
        time="2024-07-15T12:05:00Z",
        data={"ProcessGuid": "gp", "User": "a"},
    )
    socket = chain.Record(
        id="s",
        source="sysmon",
        event_id=3,
        host="h",
        time="2024-07-15T12:05:02Z",
        data={
            "ProcessGuid": "gp",
            "User": "a",
            "SourceIp": "10.0.0.1",
            "SourcePort": "12345",
            "DestinationIp": "198.51.100.70",
            "DestinationPort": "443",
            "Protocol": "tcp",
        },
    )
    wire = chain.Record(
        id="w",
        source="zeek_conn",
        event_id=0,
        host="10.0.0.1",
        time=socket.time,
        data={
            "id.orig_h": "10.0.0.1",
            "id.orig_p": "12345",
            "id.resp_h": "198.51.100.70",
            "id.resp_p": "443",
            "proto": "tcp",
            "duration": "1",
            "uid": "u",
        },
    )
    cutoff = chain.stamp("2024-07-15T12:10:00Z")
    assert (
        len(chain.sockets_with_wire(birth, "198.51.100.70", [birth, socket], [wire], cutoff)) == 1
    )
    terminal = birth.model_copy(update={"id": "exit", "event_id": 5})
    assert not chain.sockets_with_wire(
        birth, "198.51.100.70", [birth, socket, terminal], [wire], cutoff
    )


def test_preserved_c2_public_views():
    import gzip
    import json
    import os
    from pathlib import Path

    archive = os.environ.get("SCENAR_C2_ARCHIVE")
    if not archive:
        pytest.skip("Set SCENAR_C2_ARCHIVE to the qualified C2 archive")
    root = Path(archive)
    outputs = []
    for path in sorted((root / "public").glob("*.json.gz")):
        raw = gzip.decompress(path.read_bytes())
        value = json.loads(raw)
        start = value["as_of"][:10] + "T12:00:00Z"
        outputs.append(chain.find_chains(value, start))
    assert len(outputs) == 12
    assert sum(len(row["chains"]) for row in outputs) == 2
    assert all(
        c["assessment"] == "linked_remote_workflow; intent_unresolved"
        for row in outputs
        for c in row["chains"]
    )
