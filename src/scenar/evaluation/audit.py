# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Fail closed on scenario eligibility, separately from detector correctness.

This benchmark-side audit reads hidden truth. Its report is never detector input.
It does not alter the EvidenceForge evaluator or generated telemetry.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def address(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def session(value: str) -> int:
    return int(value, 16 if value.lower().startswith("0x") else 10)


def read_records(bundle: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    records = []
    hashes = {}
    for path in sorted((bundle / "data").rglob("*.xml")):
        if path.name not in {"windows_event_security.xml", "windows_event_sysmon.xml"}:
            continue
        relative = str(path.relative_to(bundle))
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        for _, node in ET.iterparse(path, events=("end",)):
            if node.tag.rsplit("}", 1)[-1] != "Event":
                continue
            records.append(
                {
                    "id": relative + "#" + node.findtext("./{*}System/{*}EventRecordID", ""),
                    "source": "security" if "security" in path.name else "sysmon",
                    "event_id": int(node.findtext("./{*}System/{*}EventID", "0")),
                    "host": node.findtext("./{*}System/{*}Computer", ""),
                    "time": node.find("./{*}System/{*}TimeCreated").attrib["SystemTime"],
                    "data": {
                        field.attrib["Name"]: field.text or ""
                        for field in node.findall("./{*}EventData/{*}Data")
                    },
                }
            )
            node.clear()
    return records, hashes


def verify(
    truth: dict[str, Any], records: list[dict[str, Any]], contract: dict[str, Any]
) -> dict[str, Any]:
    errors: list[str] = []
    cited: set[str] = set()
    required = []
    for record_id in contract["required_record_ids"]:
        matches = [e for e in truth["events"] if e["record_id"] == record_id]
        if len(matches) != 1:
            errors.append(f"{record_id}: missing or duplicate authored record")
            continue
        event = matches[0]
        required.append(event)
        if event.get("emitted") is not True:
            errors.append(f"{record_id}: not emitted ({event.get('skipped_reason', 'unknown')})")
    if errors:
        return {"eligible": False, "errors": errors, "evidence_ids": []}
    if len({e["id"] for e in records}) != len(records):
        errors.append("Duplicate source evidence IDs")
    cutoff = timestamp(contract["as_of"])
    start = truth.get("collection_window", {}).get("start")
    skew = contract.get("max_source_time_skew_seconds", 5)
    try:
        authored_times = [timestamp(e["time"]) for e in required]
    except (KeyError, ValueError):
        return {
            "eligible": False,
            "errors": ["Missing or invalid authored timestamps"],
            "evidence_ids": [],
        }
    if authored_times != sorted(authored_times) or any(t > cutoff for t in authored_times):
        errors.append("Authored actions are out of order or beyond cutoff")
    rows = [
        e
        for e in records
        if e["host"].casefold() == contract["target_host"].casefold()
        and timestamp(e["time"]) <= cutoff
        and (start is None or timestamp(e["time"]) >= timestamp(start))
    ]
    authentications = []
    for e in rows:
        d = e["data"]
        if e["source"] != "security" or e["event_id"] != 4624 or d.get("LogonType") != "10":
            continue
        if (
            d.get("TargetDomainName", "") + "\\" + d.get("TargetUserName", "")
        ).casefold() != contract["actor"].casefold():
            continue
        try:
            if (
                address(d.get("IpAddress", "")) == address(contract["source_ip"])
                and abs((timestamp(e["time"]) - authored_times[0]).total_seconds()) <= skew
            ):
                authentications.append(e)
        except ValueError:
            continue
    processes = []
    for index, command in enumerate(contract["required_commands"]):
        pid = required[index + 1]["attributes"].get("pid")
        matches = [
            e
            for e in rows
            if e["source"] == "sysmon"
            and e["event_id"] == 1
            and e["data"].get("CommandLine") == command
            and e["data"].get("ProcessId") == str(pid)
            and abs((timestamp(e["time"]) - authored_times[index + 1]).total_seconds()) <= skew
            and e["data"].get("User", "").casefold() == contract["actor"].casefold()
        ]
        if len(matches) != 1:
            errors.append(
                f"Command {index}: expected one authored Sysmon process, got {len(matches)}"
            )
            continue
        p = matches[0]
        processes.append(p)
        joins = []
        for a in authentications:
            try:
                linked = session(a["data"]["TargetLogonId"]) == session(p["data"]["LogonId"]) > 0
            except (KeyError, ValueError):
                linked = False
            if linked and timestamp(a["time"]) <= timestamp(p["time"]):
                joins.append(a)
        if len(joins) != 1:
            errors.append(f"Command {index}: expected one exact remote session, got {len(joins)}")
        else:
            cited.update([p["id"], joins[0]["id"]])
    if len(processes) == len(contract["required_commands"]):
        if timestamp(processes[0]["time"]) >= timestamp(processes[-1]["time"]):
            errors.append("Discovery must precede collection")
        if processes[0]["data"].get("LogonId") != processes[-1]["data"].get("LogonId"):
            errors.append("Discovery and collection must belong to the same session")
        archive = processes[-1]
        guid = archive["data"].get("ProcessGuid")
        files = [
            e
            for e in rows
            if e["source"] == "sysmon"
            and e["event_id"] == 11
            and e["data"].get("TargetFilename", "").casefold()
            == contract["archive_path"].casefold()
            and guid
            and e["data"].get("ProcessGuid") == guid
            and timestamp(e["time"]) >= timestamp(archive["time"])
        ]
        if not files:
            errors.append(
                "Missing archive file creation linked by ProcessGuid to collection process"
            )
        cited.update(e["id"] for e in files)
    return {"eligible": not errors, "errors": errors, "evidence_ids": sorted(cited)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("case_id")
    parser.add_argument(
        "--contracts", type=Path, default=Path(__file__).with_name("contracts.json")
    )
    args = parser.parse_args()
    contracts = json.loads(args.contracts.read_text())
    contract = next(c for c in contracts["cases"] if c["case_id"] == args.case_id)
    truth_path = args.bundle / "GROUND_TRUTH.json"
    records, hashes = read_records(args.bundle)
    result = verify(json.loads(truth_path.read_text()), records, contract)
    result.update(
        case_id=args.case_id,
        source_hashes=hashes,
        truth_sha256=hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        contract_sha256=hashlib.sha256(args.contracts.read_bytes()).hexdigest(),
    )
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["eligible"] else 1)


if __name__ == "__main__":
    main()
