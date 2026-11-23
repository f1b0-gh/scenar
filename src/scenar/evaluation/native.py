"""Private bounded reconciliation. Does not claim exhaustive action/occurrence indexing."""

from datetime import datetime
from typing import Any

from .models import Contract, Oracle, Record


def match_process(event: dict[str, Any], records: list[Record]) -> Record:
    if event.get("emitted") is not True or event.get("kind") != "process":
        raise ValueError("Required authored process was not emitted")
    attributes = event["attributes"]
    time = datetime.fromisoformat(event["time"].replace("Z", "+00:00"))
    matches = [
        r
        for r in records
        if r.source == "sysmon"
        and r.event_id == 1
        and event["system"].casefold() in {r.host.casefold(), r.host.split(".")[0].casefold()}
        and event["actor"].casefold()
        in {
            r.data.get("User", "").casefold(),
            r.data.get("User", "").rsplit("\\", 1)[-1].casefold(),
        }
        and r.data.get("CommandLine") == attributes["command_line"]
        and r.data.get("Image", "").casefold() == attributes["process_name"].casefold()
        and r.data.get("ProcessId") == str(attributes["pid"])
        and r.data.get("ProcessGuid")
        and abs((r.time - time).total_seconds()) <= 5
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Missing or ambiguous native process for {event['record_id']}: {len(matches)}"
        )
    return matches[0]


def reconcile(
    truth: dict[str, Any], records: list[Record], contract: Contract, hashes: dict[str, str]
) -> tuple[Oracle, list[dict[str, Any]]]:
    if len({r.id for r in records}) != len(records):
        raise ValueError("Duplicate native IDs")
    actions: dict[str, list[str]] = {}
    index: list[dict[str, Any]] = []
    matched: set[str] = set()
    for member in contract.members:
        authored = [e for e in truth["events"] if e["record_id"] == member.authored_record_id]
        if len(authored) != 1:
            raise ValueError("Missing or duplicate authored member")
        event = authored[0]
        row = match_process(event, records)
        if row.id in matched:
            raise ValueError("Distinct authored processes mapped to the same observation")
        matched.add(row.id)
        source, separator, record_id = row.id.rpartition("#")
        if not separator or not record_id or source not in hashes:
            raise ValueError("Native observation has no hashed file/record locator")
        if member.role == "action":
            actions[row.id] = member.episode_ids
        index.append(
            {
                "authored_record_id": member.authored_record_id,
                "intent_id": event.get("intent_id"),
                "observation_id": row.id,
                "native_file": source,
                "native_record_id": record_id,
                "native_file_sha256": hashes[source],
                "source_time": row.time.isoformat(),
                "available_at_assumption": row.time.isoformat(),
                "role": member.role,
                "episode_ids": member.episode_ids,
            }
        )
    return Oracle(
        episodes=contract.episodes,
        actions=actions,
        useful_evidence=[r["observation_id"] for r in index],
    ), index


def reconcile_case(
    truth: dict[str, Any], records: list[Record], case: dict[str, Any], hashes: dict[str, str]
) -> tuple[Oracle, list[dict[str, Any]]]:
    """Qualify all required identities and the authored parent topology."""
    contract = Contract.model_validate(case["private"])
    oracle, index = reconcile(truth, records, contract, hashes)
    # Qualify the declared shell topology against source GUIDs, not just matching commands.
    by_id = {r.id: r for r in records}
    mapped = {i["authored_record_id"]: by_id[i["observation_id"]] for i in index}
    shared = case["family"] == "independent_shared_parent"
    for j in range(len(case["audits"])):
        parent = mapped[f"shell-{0 if shared else j}#0"]
        for action in ("discover", "archive"):
            child = mapped[f"{action}-{j}#0"]
            if (
                child.data.get("ParentProcessGuid") != parent.data.get("ProcessGuid")
                or child.host != parent.host
                or parent.time > child.time
            ):
                raise ValueError("Authored parent does not match native lineage")
    return oracle, index
