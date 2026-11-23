"""Public-only C2-shaped chain proof; observed linkage is not malicious intent."""

import json
from datetime import datetime

from . import bench, observations, proof, public_adapter
from . import wire as followup
from .models import Candidate, Record


def stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def exact_parent(parent: Record, child: Record) -> bool:
    return (
        parent.source == child.source == "sysmon"
        and parent.event_id == child.event_id == 1
        and parent.host.casefold() == child.host.casefold()
        and parent.time < child.time
        and bool(parent.data.get("ProcessGuid"))
        and child.data.get("ParentProcessGuid") == parent.data["ProcessGuid"]
        and all(
            parent.data.get(k) and parent.data[k].casefold() == child.data.get(k, "").casefold()
            for k in ("User", "LogonId")
        )
    )


def wire_match(socket: Record, wire: Record, cutoff: datetime) -> bool:
    return (
        bool(wire.data.get("uid"))
        and followup.wire_matches(socket, wire)
        and followup.wire_available(wire, cutoff)
    )


def sockets_with_wire(
    birth: Record,
    destination: str,
    records: list[Record],
    wire: list[Record],
    cutoff: datetime,
    before: datetime | None = None,
) -> list[tuple[Record, Record]]:
    """Retain every observed process-owned contact; never equate TLS contacts with tasks."""
    contacts = [
        r
        for r in records
        if r.source == "sysmon"
        and r.event_id == 3
        and r.host == birth.host
        and r.data.get("ProcessGuid") == birth.data.get("ProcessGuid")
        and r.data.get("User", "").casefold() == birth.data.get("User", "").casefold()
        and r.data.get("DestinationIp") == destination
        and r.data.get("DestinationPort") == "443"
        and r.data.get("Protocol", "").casefold() == "tcp"
        and birth.time <= r.time <= cutoff
        and (before is None or r.time < before)
    ]
    terminals = [
        r.time
        for r in records
        if r.source == "sysmon"
        and r.event_id == 5
        and r.host == birth.host
        and r.data.get("ProcessGuid") == birth.data.get("ProcessGuid")
    ]
    if any(t <= n.time for t in terminals for n in contacts):
        return []
    pairs = []
    for contact in contacts:
        matches = [w for w in wire if wire_match(contact, w, cutoff)]
        if len(matches) != 1:
            return []
        pairs.append((contact, matches[0]))
    if len({s.id for s, w in pairs}) != len(pairs) or len({w.data["uid"] for s, w in pairs}) != len(
        pairs
    ):
        return []
    return pairs


def workflow(
    c: Candidate, records: list[Record], wire: list[Record], cutoff: datetime
) -> dict | None:
    """Existing inventory/archive proof plus a unique uploader with all corroborated sockets."""
    rows = observations.group(c, records)
    edges = [e for e in bench.chain_edges(rows) if e[1] == c.record.id]
    support = proof.chain_support(c, rows, True)
    if len(edges) != 1 or not support:
        return None
    by_id = {r.id: r for r in records}
    parents = [
        r
        for r in rows
        if r.event_id == 1 and r.data.get("ProcessGuid") == c.record.data.get("ParentProcessGuid")
    ]
    if len(parents) != 1:
        return None
    parent = parents[0]
    children = [by_id[i] for i in edges[0]]
    if any(
        r.source == "sysmon"
        and r.event_id == 5
        and r.host == parent.host
        and r.data.get("ProcessGuid") == parent.data.get("ProcessGuid")
        and r.time <= child.time
        for r in records
        for child in children
    ):
        return None
    if not all(exact_parent(parent, by_id[i]) for i in edges[0]):
        return None
    files = [by_id[i] for i in support if by_id[i].event_id == 11]
    if not files:
        return None
    uploads = []
    for r in rows:
        if r.event_id != 1 or not exact_parent(parent, r):
            continue
        if any(
            t.source == "sysmon"
            and t.event_id == 5
            and t.host == parent.host
            and t.data.get("ProcessGuid") == parent.data.get("ProcessGuid")
            and t.time <= r.time
            for t in records
        ):
            continue
        match = observations.UPLOAD.fullmatch(r.data.get("CommandLine", ""))
        if (
            match
            and match["path"].casefold() == c.output_path
            and max(f.time for f in files) <= r.time
        ):
            pairs = sockets_with_wire(r, match["destination"], records, wire, cutoff)
            if pairs:
                uploads.append((r, match["destination"], pairs))
    if len(uploads) != 1:
        return None
    upload, destination, pairs = uploads[0]
    evidence = sorted(set(support + [upload.id] + [r.id for pair in pairs for r in pair]))
    return {
        "parent": parent,
        "upload": upload,
        "destination": destination,
        "pairs": pairs,
        "evidence_ids": evidence,
    }


def find_chains(public: dict, start: str) -> dict:
    """Full bounded observation query: proves lineage, not received tasks or maliciousness."""
    retest = public_adapter
    snap, wire, _ = retest.adapt(public, start)
    records = snap.records
    births = [r for r in records if r.source == "sysmon" and r.event_id == 1]
    chains = []
    for c in bench.candidates(snap):
        if c.action != "archive":
            continue
        described = workflow(c, records, wire, snap.as_of)
        if described is None:
            continue
        shell = described["parent"]
        owners = [r for r in births if exact_parent(r, shell)]
        if len(owners) != 1:
            continue
        owner = owners[0]
        identities = [(r.host, r.data.get("ProcessGuid")) for r in births]
        involved = [owner, shell, c.record, described["upload"]]
        if any(identities.count((r.host, r.data.get("ProcessGuid"))) != 1 for r in involved):
            continue
        if any(
            r.source == "sysmon"
            and r.event_id == 5
            and r.host == owner.host
            and r.data.get("ProcessGuid") == owner.data["ProcessGuid"]
            and r.time <= shell.time
            for r in records
        ):
            continue
        destinations = sorted(
            {
                r.data.get("DestinationIp", "")
                for r in records
                if r.source == "sysmon"
                and r.event_id == 3
                and r.host == owner.host
                and r.data.get("ProcessGuid") == owner.data["ProcessGuid"]
            }
        )
        for dest in destinations:
            pairs = sockets_with_wire(owner, dest, records, wire, snap.as_of, before=shell.time)
            if (
                len(pairs) < 3
                or (max(s.time for s, w in pairs) - min(s.time for s, w in pairs)).total_seconds()
                < 10
            ):
                continue
            evidence = sorted(
                set(
                    described["evidence_ids"]
                    + [owner.id, shell.id]
                    + [r.id for pair in pairs for r in pair]
                )
            )
            chains.append(
                {
                    "controller": owner.id,
                    "shell": shell.id,
                    "archive": c.record.id,
                    "callback_destination": dest,
                    "callback_contacts": len(pairs),
                    "transfer_destination": described["destination"],
                    "transfer_contacts": len(described["pairs"]),
                    "evidence_ids": evidence,
                    "assessment": "linked_remote_workflow; intent_unresolved",
                }
            )
    return {
        "chains": chains,
        "scanned_records": len(public["records"]),
        "scanned_bytes": len(json.dumps(public).encode()),
        "scope": "Full public scan, not a budget-matched investigator or a maliciousness classifier",
    }
