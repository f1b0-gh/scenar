"""Deterministic views of audited native bytes with restricted collection receipts."""

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..io import canonical, files
from .audit import NATIVE_FILENAMES
from .visibility import VisibilitySettings, _deployed_sources, apply_visibility

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class ReceiptModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RecordReceipt(ReceiptModel):
    native_file: str
    record_id: str
    source_instance: str
    source_time_ns: int
    available_at_ns: int | None
    included: bool
    reason: Literal["collected", "lost", "disabled", "not_yet_available", "availability_unknown"]


class VisibilityReceipt(ReceiptModel):
    schema_version: Literal["scenar/visibility-receipt/v1"] = "scenar/visibility-receipt/v1"
    settings: VisibilitySettings
    seed: int = Field(ge=0, le=2**64 - 1)
    cutoff_ns: int
    source_hashes: dict[str, str]
    output_hashes: dict[str, str]
    records: list[RecordReceipt]

    @property
    def view_id(self) -> str:
        return hashlib.sha256(canonical(self.model_dump(mode="json"))).hexdigest()


def instant_ns(value: datetime | str) -> int:
    if isinstance(value, str):
        match = re.fullmatch(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
            value,
        )
        if match is None:
            raise ValueError("Invalid native timestamp or unsupported precision")
        whole, fraction, zone = match.groups()
        parsed = datetime.fromisoformat(whole + zone.replace("Z", "+00:00"))
        return instant_ns(parsed) + int((fraction or "").ljust(9, "0"))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Native timestamp must include timezone")
    delta = value.astimezone(timezone.utc) - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000000000 + delta.microseconds * 1000


def _zeek_ns(value: str | Decimal | int) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, Decimal, int)):
        raise ValueError("Zeek time/duration must be a numeric value, not a boolean or null")
    timestamp = Decimal(value)
    if not timestamp.is_finite():
        raise ValueError("Invalid Zeek timestamp")
    numerator, denominator = timestamp.as_integer_ratio()
    whole, remainder = divmod(numerator * 1000000000, denominator)
    if remainder:
        raise ValueError("Zeek timestamp exceeds nanosecond precision")
    return whole


def derive_view(
    native: Path,
    scenario: dict,
    settings: VisibilitySettings,
    *,
    seed: int,
    cutoff: datetime,
) -> tuple[dict[str, bytes], VisibilityReceipt]:
    """Filter XML/Zeek records; never modify native input or infer private action labels."""
    settings = VisibilitySettings.model_validate(settings.model_dump())
    apply_visibility(scenario, settings)  # Validate exact deployed selectors and conflicts.
    sources, _ = _deployed_sources(scenario)
    # Only sources selected by this treatment receive a *derived* intervention.
    if settings.hosts is not None:
        selected = {
            s
            for s in sources
            if s.split(":")[1] in settings.hosts and s.split(":")[0] not in {"zeek", "ids", "asa"}
        }
    elif settings.source_instances is not None:
        selected = set(settings.source_instances)
    else:
        selected = sources
    if settings.mode == "missing_endpoint":
        owners = {s.split(":")[1] for s in selected}
        selected = {
            s
            for s in sources
            if s.split(":")[1] in owners and s.split(":")[0] in {"sysmon", "windows_security"}
        }
    cutoff_ns = instant_ns(cutoff)
    inventory = {
        n: sha
        for n, sha in files(native).items()
        if n.startswith("data/") and Path(n).name in NATIVE_FILENAMES
    }
    receipts = []
    outputs = {}
    seen = set()

    def collect(
        name: str, record: str, source: str, timestamp: int, duration_ns: int | None = 0
    ) -> bool:
        if not record or (name, record) in seen:
            raise ValueError("Missing or duplicate native record identity")
        seen.add((name, record))
        delay = settings.delay_us if settings.mode == "delayed" and source in selected else 0
        available = None if duration_ns is None else timestamp + duration_ns + (delay or 0) * 1000
        reason = "collected"
        if source in selected:
            if settings.mode == "missing_endpoint":
                reason = "disabled"
            elif settings.mode == "lossy":
                draw = int.from_bytes(
                    hashlib.sha256(canonical([seed, name, record])).digest(), "big"
                )
                numerator, denominator = Decimal(str(settings.probability)).as_integer_ratio()
                if draw * denominator < numerator * 2**256:
                    reason = "lost"
        if reason == "collected":
            if available is None:
                reason = "availability_unknown"
            elif available > cutoff_ns:
                reason = "not_yet_available"
        receipts.append(
            RecordReceipt(
                native_file=name,
                record_id=record,
                source_instance=source,
                source_time_ns=timestamp,
                available_at_ns=available,
                included=reason == "collected",
                reason=reason,
            )
        )
        return reason == "collected"

    def source_for(family: str, owner: str) -> str:
        owner = owner.casefold()
        matches = [
            s
            for s in sources
            if s.split(":")[0] == family
            and (
                owner == s.split(":")[1]
                or ("." not in s.split(":")[1] and owner.split(".")[0] == s.split(":")[1])
                or ("." not in owner and owner == s.split(":")[1].split(".")[0])
            )
        ]
        if family == "zeek":
            for sensor in scenario.get("environment", {}).get("network", {}).get("sensors", []):
                identity = "zeek:" + sensor["name"].casefold()
                aliases = {sensor["name"].casefold(), sensor.get("hostname", "").casefold()}
                if identity in sources and owner in aliases:
                    matches.append(identity)
            matches = sorted(set(matches))
        if len(matches) != 1:
            raise ValueError(f"Unknown or ambiguous native source: {family}:{owner}")
        return matches[0]

    for name in inventory:
        path = native / name
        if path.suffix == ".xml":
            raw = path.read_bytes()
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ValueError("Unsupported native XML declaration")
            try:
                root = ET.fromstring(raw)
            except ET.ParseError as exc:
                raise ValueError("Invalid native XML") from exc
            if root.tag != "Events":
                raise ValueError("Expected native Events XML container")
            family = "sysmon" if path.name == "windows_event_sysmon.xml" else "windows_security"
            for event in list(root):
                if event.tag != NS + "Event":
                    raise ValueError("Unsupported native XML record")
                system = event.find(NS + "System")
                if system is None:
                    raise ValueError("Missing native XML System")
                host = system.findtext(NS + "Computer")
                record = system.findtext(NS + "EventRecordID")
                time = system.find(NS + "TimeCreated")
                if not host or not record or time is None or "SystemTime" not in time.attrib:
                    raise ValueError("Missing native XML identity or timestamp")
                source = source_for(family, host)
                if not collect(name, record, source, instant_ns(time.attrib["SystemTime"])):
                    root.remove(event)
            outputs[name] = ET.tostring(root, encoding="utf-8") + b"\n"
        else:
            source = source_for("zeek", path.parent.name)
            kept = []
            fields = None
            separator = "\t"
            for line in path.read_text().splitlines(keepends=True):
                if line.startswith("#separator "):
                    separator = bytes(line.strip().split(" ", 1)[1], "ascii").decode(
                        "unicode_escape"
                    )
                elif line.startswith("#fields"):
                    fields = line.rstrip("\r\n").split(separator)[1:]
                if line.startswith("#") or not line.strip():
                    kept.append(line)
                    continue
                if line.lstrip().startswith("{"):
                    row = json.loads(line, parse_float=Decimal)
                elif fields is not None:
                    row = dict(zip(fields, line.rstrip("\r\n").split(separator), strict=True))
                else:
                    raise ValueError("Missing Zeek field header")
                if not isinstance(row, dict):
                    raise ValueError("Expected a Zeek record object")
                uid = row.get("uid")
                if (
                    not isinstance(uid, str)
                    or not uid
                    or uid == "-"
                    or any(c.isspace() for c in uid)
                ):
                    raise ValueError("Missing or invalid Zeek UID")
                transaction = row.get("trans_id", "-")
                if isinstance(transaction, bool) or not isinstance(transaction, (str, int)):
                    raise ValueError("Invalid Zeek transaction identity")
                record = (
                    uid if path.stem == "conn" else f"{uid}:{row.get('trans_id', '-')}:{row['ts']}"
                )
                duration_ns = 0
                if path.stem == "conn":
                    duration = row.get("duration")
                    duration_ns = None if duration in (None, "-") else _zeek_ns(duration)
                    if duration_ns is not None and duration_ns < 0:
                        raise ValueError("Connection duration must be nonnegative")
                elif path.stem == "dns":
                    duration = row.get("rtt")
                    if duration not in (None, "-"):
                        duration_ns = _zeek_ns(duration)
                        if duration_ns < 0:
                            raise ValueError("DNS RTT must be nonnegative")
                    else:
                        duration_ns = None
                if collect(name, record, source, _zeek_ns(row["ts"]), duration_ns):
                    kept.append(line)
            outputs[name] = "".join(kept).encode()
    receipt = VisibilityReceipt(
        settings=settings,
        seed=seed,
        cutoff_ns=cutoff_ns,
        source_hashes=inventory,
        output_hashes={n: hashlib.sha256(b).hexdigest() for n, b in outputs.items()},
        records=receipts,
    )
    return outputs, receipt
