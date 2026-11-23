"""Private, source-backed reconciliation of a bounded set of authored effects.

This does not index every upstream occurrence or label ambient records. Backend
acceptance is deliberately separate from this native evidence verdict.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, Self
from xml.etree.ElementTree import ParseError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scenar.evaluation.audit import read_records, session
from scenar.scenario import authored_cardinality
from scenar.truth import authored_identity_map

NATIVE_FILENAMES = frozenset(
    {
        "windows_event_sysmon.xml",
        "windows_event_security.xml",
        "conn.json",
        "dns.json",
        "conn.log",
        "dns.log",
    }
)

# A recognized event ID alone is not a sufficient effect signature.
_REQUIRED: dict[tuple[str, int | str], set[str]] = {
    ("sysmon", 1): {"Image", "CommandLine", "User"},
    ("sysmon", 3): {"DestinationIp", "DestinationPort", "Protocol"},
    ("sysmon", 10): {"TargetImage", "GrantedAccess"},
    ("sysmon", 11): {"TargetFilename"},
    ("sysmon", 12): {"TargetObject", "EventType"},
    ("sysmon", 13): {"TargetObject", "Details"},
    ("security", 4624): {"TargetUserName", "TargetDomainName", "LogonType", "IpAddress"},
    ("security", 4697): {"ServiceName", "ServiceFileName"},
    ("security", 4698): {"TaskName", "SubjectUserName"},
    ("zeek", "conn"): {"id.orig_h", "id.resp_h", "id.resp_p", "proto"},
    ("zeek", "dns"): {"id.orig_h", "id.resp_h", "query"},
}
_CASEFOLD = {
    "Image",
    "User",
    "TargetFilename",
    "TargetImage",
    "TargetObject",
    "TargetUserName",
    "TargetDomainName",
    "SubjectUserName",
    "SubjectDomainName",
    "ServiceFileName",
    "Protocol",
    "proto",
}
_IP_FIELDS = {"IpAddress", "SourceIp", "DestinationIp", "id.orig_h", "id.resp_h"}


def _instant(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone")
    return result


def _duration(value: str) -> timedelta:
    match = re.fullmatch(r"(\d+)([smhd])", value)
    if match is None or int(match[1]) <= 0:
        raise ValueError("Duration must be positive integer seconds, minutes, hours or days")
    return timedelta(seconds=int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]])


def collection_window(scenario: dict) -> tuple[datetime, datetime]:
    """Resolve the backend's explicit-end or start-plus-duration window."""
    window = scenario["time_window"]
    start = _instant(window["start"])
    end = _instant(window["end"]) if window.get("end") else start + _duration(window["duration"])
    if start > end:
        raise ValueError("Collection window is reversed")
    return start, end


def _beacon_timing(
    exp: EffectExpectation, scenario: dict, start: datetime
) -> tuple[datetime, timedelta, float] | None:
    """Resolve an explicit deterministic tick, without inventing occurrence IDs."""
    sid, separator, ordinal = exp.authored_event_id.rpartition("#")
    if not separator or not ordinal.isdigit() or exp.source != "zeek":
        return None
    for section in ("storyline", "red_herrings"):
        for step in scenario.get(section) or []:
            if step["id"] != sid:
                continue
            spec = step["events"][int(ordinal)]
            if spec["type"] != "beacon":
                return None
            if spec.get("jitter") != 0 or type(spec.get("count")) is not int:
                raise ValueError("Beacon audit requires explicit count and zero interval jitter")
            value = spec.get("start_time") or step["time"]
            anchor = start + _duration(value[1:]) if value.startswith("+") else _instant(value)
            interval = _duration(spec["interval"]).total_seconds()
            offset = _instant(exp.time) - anchor
            tick = offset.total_seconds() / interval
            if tick < 0 or not tick.is_integer() or tick >= spec["count"]:
                raise ValueError("Beacon expectation is not a declared tick")
            return anchor, offset, min(exp.tolerance_seconds, 5.0, interval / 3)
    return None


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def strict_version(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("Schema version must be an integer")
        return value


class EffectRelationship(_Contract):
    expectation_id: str = Field(min_length=1)
    field: str = Field(min_length=1)
    target_field: str = Field(min_length=1)
    kind: Literal["process_guid", "logon_id"] = "process_guid"

    @model_validator(mode="after")
    def identity_fields(self) -> Self:
        if self.kind == "process_guid":
            valid = (
                self.field in {"ProcessGuid", "ParentProcessGuid", "SourceProcessGUID"}
                and self.target_field == "ProcessGuid"
            )
        else:
            valid = (
                self.field in {"LogonId", "SubjectLogonId"} and self.target_field == "TargetLogonId"
            )
        if not valid:
            raise ValueError("Relationship must join native process or logon identity fields")
        return self


class EffectExpectation(_Contract):
    schema_version: Literal[1] = 1
    id: str = Field(min_length=1)
    authored_event_id: str = Field(min_length=1)
    source: Literal["sysmon", "security", "zeek"]
    event_id: int | str
    host: str = Field(min_length=1)
    time: str
    tolerance_seconds: int = Field(default=5, ge=0, le=300)
    fields: dict[str, str]
    relationship: EffectRelationship | None = None

    @field_validator("time")
    @classmethod
    def aware_time(cls, value: str) -> str:
        _instant(value)
        return value

    @model_validator(mode="after")
    def sufficient_signature(self) -> Self:
        required = _REQUIRED.get((self.source, self.event_id))
        if required and (
            not required <= self.fields.keys() or any(not self.fields[key] for key in required)
        ):
            raise ValueError(f"Effect requires native fields: {sorted(required)}")
        if self.source == "sysmon" and self.event_id in {3, 10, 11, 12, 13}:
            field = "SourceProcessGUID" if self.event_id == 10 else "ProcessGuid"
            if (
                self.relationship is None
                or self.relationship.kind != "process_guid"
                or self.relationship.field != field
            ):
                raise ValueError("Effect must be linked to its exact native process")
        return self


class NativeReference(_Contract):
    evidence_id: str
    native_file: str
    native_record_id: str
    native_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_time: str


class EffectResult(_Contract):
    expectation_id: str
    status: Literal["observed", "missing", "ambiguous", "unsupported"]
    evidence_ids: list[str] = Field(default_factory=list)
    evidence: list[NativeReference] = Field(default_factory=list)
    truth_record_ids: list[str] = Field(default_factory=list)
    reason: str


class AuditReport(_Contract):
    schema_version: Literal[1] = 1
    passed: bool
    effects: list[EffectResult]
    source_hashes: dict[str, str]
    truth_sha256: str | None
    errors: list[str] = Field(default_factory=list)
    scope: Literal["authored_expectations_only"] = "authored_expectations_only"
    ambient_labels: Literal["unknown"] = "unknown"

    @model_validator(mode="after")
    def consistent_verdict(self) -> Self:
        expected = (
            bool(self.effects)
            and not self.errors
            and all(e.status == "observed" for e in self.effects)
        )
        if self.passed != expected:
            raise ValueError("Audit verdict does not match effect outcomes")
        return self


def _zeek_records(native: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    records: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    for path in sorted((native / "data").rglob("*")):
        if path.name not in {"conn.json", "dns.json", "conn.log", "dns.log"} or not path.is_file():
            continue
        relative = path.relative_to(native).as_posix()
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        fields: list[str] | None = None
        separator = "\t"
        for line in path.read_text().splitlines():
            if line.startswith("#separator "):
                separator = bytes(line.split(" ", 1)[1], "ascii").decode("unicode_escape")
            elif line.startswith("#fields"):
                fields = line.split(separator)[1:]
            elif line and not line.startswith("#"):
                if line.startswith("{"):
                    data = json.loads(line, parse_float=Decimal)
                elif fields is not None:
                    values = line.split(separator)
                    if len(values) != len(fields):
                        raise ValueError(f"Invalid Zeek row in {relative}")
                    data = dict(zip(fields, values, strict=True))
                else:
                    raise ValueError(f"Missing Zeek field header in {relative}")
                uid = str(data["uid"])
                if not uid or uid == "-":
                    raise ValueError(f"Missing Zeek UID in {relative}")
                # DNS has multiple transactions per connection; preserve that native identity.
                record_id = (
                    uid
                    if path.stem == "conn"
                    else f"{uid}:{data.get('trans_id', '-')}:{data['ts']}"
                )
                records.append(
                    {
                        "id": f"{relative}#{record_id}",
                        "source": "zeek",
                        "event_id": path.stem,
                        "host": path.parent.name,
                        "time": datetime.fromtimestamp(float(data["ts"]), UTC).isoformat(),
                        "data": {key: str(value) for key, value in data.items()},
                    }
                )
    return records, hashes


def _equal(field: str, actual: str | None, expected: str) -> bool:
    if actual is None:
        return False
    if field in _IP_FIELDS:
        try:
            left, right = ipaddress.ip_address(actual), ipaddress.ip_address(expected)
            return (getattr(left, "ipv4_mapped", None) or left) == (
                getattr(right, "ipv4_mapped", None) or right
            )
        except ValueError:
            return False
    return actual.casefold() == expected.casefold() if field in _CASEFOLD else actual == expected


def _linked(row: dict[str, Any], target: dict[str, Any], relation: EffectRelationship) -> bool:
    if row["host"].casefold() != target["host"].casefold() or _instant(target["time"]) > _instant(
        row["time"]
    ):
        return False
    left, right = row["data"].get(relation.field), target["data"].get(relation.target_field)
    if not left or not right:
        return False
    if relation.kind == "process_guid":
        return left.casefold() == right.casefold() and left.strip("{}0-") != ""
    try:
        return session(left) == session(right) > 0
    except ValueError:
        return False


def audit_native(
    native: Path, scenario: dict, expectations: list[EffectExpectation]
) -> AuditReport:
    """Match each declared effect against actual native records, failing closed.

    Truth supplies authored identity/PID and emission intent, never substitutes
    for observed source records. Bounded upstream action samples are not read as
    an exhaustive occurrence index. Only the declared collection window is used.
    """
    expectations = [EffectExpectation.model_validate(e.model_dump()) for e in expectations]
    by_id = {e.id: e for e in expectations}
    if len(by_id) != len(expectations):
        raise ValueError("Duplicate expectation IDs")
    for exp in expectations:
        relation = exp.relationship
        if relation:
            if relation.expectation_id not in by_id:
                raise ValueError("Relationship references an unknown expectation")
            target = by_id[relation.expectation_id]
            expected_source = (
                ("sysmon", 1) if relation.kind == "process_guid" else ("security", 4624)
            )
            if (target.source, target.event_id) != expected_source:
                raise ValueError("Relationship references the wrong native identity type")
    errors: list[str] = []
    hashes: dict[str, str] = {}
    truth_hash = None
    results: dict[str, EffectResult] = {}
    matched: dict[str, dict[str, Any]] = {}
    try:
        # Never follow files or directories out of the native capture.
        if native.is_symlink():
            raise ValueError("Native capture root is a symlink")
        for path in native.rglob("*"):
            if path.is_symlink():
                raise ValueError("Native capture contains a symlink")
        truth_path = native / "GROUND_TRUTH.json"
        truth_bytes = truth_path.read_bytes()
        truth_hash = hashlib.sha256(truth_bytes).hexdigest()
        truth = json.loads(truth_bytes)
        events = truth["events"]
        if not isinstance(events, list):
            raise ValueError("Native truth events must be a list")
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get("record_id"), str):
                raise ValueError("Native truth event lacks a record identity")
            _instant(event["time"])
        ids = [e["record_id"] for e in events]
        if len(ids) != len(set(ids)):
            errors.append("Duplicate truth record IDs")
        start, end = collection_window(scenario)
        truth_window = truth["collection_window"]
        if _instant(truth_window["start"]) != start or _instant(truth_window["end"]) != end:
            raise ValueError("Native truth collection window differs from scenario")
        identities = authored_identity_map(
            truth,
            required_ids={e.authored_event_id for e in expectations if "#" in e.authored_event_id},
            authored_counts=authored_cardinality(scenario),
        )
        beacon_timing = {e.id: _beacon_timing(e, scenario, start) for e in expectations}
        records, hashes = read_records(native)
        zeek, zeek_hashes = _zeek_records(native)
        records += zeek
        hashes.update(zeek_hashes)
        ids = [r["id"] for r in records]
        if len(ids) != len(set(ids)):
            errors.append("Duplicate native source evidence IDs")
        for row in records:
            if not row["id"].rpartition("#")[2] or not row["host"]:
                raise ValueError("Native record has no source identity or host")
            _instant(row["time"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ParseError) as exc:
        errors.append(f"Invalid native audit input: {exc}")
        return AuditReport(
            passed=False,
            effects=[
                EffectResult(
                    expectation_id=e.id,
                    status="missing",
                    reason="Native input could not be validated",
                )
                for e in sorted(expectations, key=lambda e: e.id)
            ],
            source_hashes=hashes,
            truth_sha256=truth_hash,
            errors=errors,
        )

    visiting: set[str] = set()

    def reconcile(exp: EffectExpectation) -> None:
        if exp.id in results:
            return
        if exp.id in visiting:
            raise ValueError("Cyclic effect relationships")
        visiting.add(exp.id)
        relation = exp.relationship
        if relation:
            reconcile(by_id[relation.expectation_id])
        status: Literal["observed", "missing", "ambiguous", "unsupported"] = "missing"
        reason = "No matching native effect"
        candidates: list[dict[str, Any]] = []
        instant = _instant(exp.time)
        timing = beacon_timing[exp.id]
        authored_instant = timing[0] if timing else instant
        authored = [
            e
            for e in events
            if (
                identities[e["record_id"]] == exp.authored_event_id
                if "#" in exp.authored_event_id
                else e.get("storyline_id") == exp.authored_event_id
            )
        ]
        authored = [
            e
            for e in authored
            if e.get("emitted") is True
            and start <= _instant(e["time"]) <= end
            and abs((_instant(e["time"]) - authored_instant).total_seconds())
            <= exp.tolerance_seconds
        ]
        if exp.source != "zeek":
            authored = [
                e
                for e in authored
                if str(e.get("system", "")).casefold()
                in {exp.host.casefold(), exp.host.split(".")[0].casefold()}
            ]
        if exp.source == "sysmon" and exp.event_id == 1:
            authored = [e for e in authored if e.get("kind") == "process"]
        if (exp.source, exp.event_id) not in _REQUIRED:
            status, reason = "unsupported", "No native adapter for this source/event effect"
        elif "#" not in exp.authored_event_id and len(authored) > 1:
            status, reason = "ambiguous", "Bare authored step refers to multiple native intents"
        elif not start <= instant <= end:
            reason = "Expectation falls outside collection window"
        elif not authored:
            reason = "No emitted authored intent in the collection/time window"
        elif relation and relation.expectation_id not in matched:
            reason = "Required native relationship was not uniquely observed"
        else:
            for row in records:
                if (
                    row["source"] != exp.source
                    or row["event_id"] != exp.event_id
                    or row["host"].casefold() != exp.host.casefold()
                ):
                    continue
                time = _instant(row["time"])
                expected_times = (
                    [(_instant(e["time"]) + timing[1], timing[2]) for e in authored]
                    if timing
                    else [(instant, exp.tolerance_seconds)]
                )
                if not start <= time <= end or not any(
                    abs((time - target).total_seconds()) <= tolerance
                    for target, tolerance in expected_times
                ):
                    continue
                if not all(
                    _equal(field, row["data"].get(field), value)
                    for field, value in exp.fields.items()
                ):
                    continue
                if exp.source == "sysmon" and exp.event_id == 1:
                    # A command string alone cannot identify the authored process.
                    if not row["data"].get("ProcessGuid") or not any(
                        str(e.get("attributes", {}).get("pid", "")) == row["data"].get("ProcessId")
                        and abs((_instant(e["time"]) - time).total_seconds()) <= 5
                        for e in authored
                    ):
                        continue
                if relation and not _linked(row, matched[relation.expectation_id], relation):
                    continue
                candidates.append(row)
            if len(candidates) == 1:
                status, reason = "observed", "Unique native effect matched"
                matched[exp.id] = candidates[0]
            elif len(candidates) > 1:
                status, reason = "ambiguous", "Multiple native records satisfy the effect"
        refs = []
        for row in sorted(candidates, key=lambda r: r["id"]):
            path, _, source_id = row["id"].rpartition("#")
            refs.append(
                NativeReference(
                    evidence_id=row["id"],
                    native_file=path,
                    native_record_id=source_id,
                    native_file_sha256=hashes[path],
                    source_time=row["time"],
                )
            )
        results[exp.id] = EffectResult(
            expectation_id=exp.id,
            status=status,
            reason=reason,
            evidence_ids=[r.evidence_id for r in refs],
            evidence=refs,
            truth_record_ids=sorted(e["record_id"] for e in authored),
        )
        visiting.remove(exp.id)

    for exp in sorted(expectations, key=lambda e: e.id):
        reconcile(exp)
    # Distinct expectations cannot reuse one observation to claim multiple effects.
    used: dict[str, str] = {}
    for key, row in matched.items():
        if row["id"] in used:
            errors.append(f"Native evidence reused by expectations {used[row['id']]} and {key}")
        used[row["id"]] = key
    effects = [results[key] for key in sorted(results)]
    passed = bool(effects) and not errors and all(e.status == "observed" for e in effects)
    return AuditReport(
        passed=passed,
        effects=effects,
        source_hashes=dict(sorted(hashes.items())),
        truth_sha256=truth_hash,
        errors=sorted(errors),
    )
