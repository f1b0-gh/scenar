"""Compile visibility treatments to pinned EvidenceForge collection overrides.

``complete`` preserves the authored collection policy. ``delayed`` requests source
batching, an approximation of delivery delay, never a guaranteed fixed per-record
delay or a manufactured availability timestamp. The format/platform mapping below
matches the pinned backend's source catalog and deployment compiler (revision 162).
"""

import re
from copy import deepcopy
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]*")
_SOURCE = re.compile(r"[a-z0-9][a-z0-9._-]*:[a-z0-9][a-z0-9._-]*(?::[a-z0-9][a-z0-9._-]*)?")
_ZEEK = {
    "zeek_conn",
    "zeek_dns",
    "zeek_http",
    "zeek_smtp",
    "zeek_ssl",
    "zeek_files",
    "zeek_smb_files",
    "zeek_smb_mapping",
    "zeek_x509",
    "zeek_dhcp",
    "zeek_ntp",
    "zeek_weird",
    "zeek_ocsp",
    "zeek_pe",
    "zeek_packet_filter",
    "zeek_reporter",
}
# format -> (source family, allowed platforms, required role)
_HOST_FORMATS = {
    "windows_event_sysmon": ("sysmon", {"windows"}, None),
    "windows_event_security": ("windows_security", {"windows"}, None),
    "ecar": ("ecar", {"windows", "linux"}, None),
    "syslog": ("syslog", {"linux"}, None),
    "bash_history": ("bash_history", {"linux"}, None),
    "proxy_access": ("proxy", {"windows", "linux"}, "forward-proxy"),
    "web_access": ("web", {"windows", "linux"}, "web-server"),
}
_SENSOR_FORMATS = {name: ("zeek", "network") for name in _ZEEK} | {
    "snort_alert": ("ids", "ids"),
    "cisco_asa": ("asa", "firewall"),
}


class VisibilitySettings(BaseModel):
    """Explicit collection treatment; omitted selectors mean all deployed sources.

    Missing-endpoint treatments require a host or exact Windows source selection
    and disable both Windows Security and Sysmon on each selected endpoint.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["scenar/visibility/v1"] = "scenar/visibility/v1"
    mode: Literal["complete", "lossy", "delayed", "missing_endpoint"] = "complete"
    probability: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    delay_us: int | None = Field(default=None, gt=0)
    source_instances: list[str] | None = Field(default=None, min_length=1)
    hosts: list[str] | None = Field(default=None, min_length=1)

    @field_validator("source_instances", "hosts")
    @classmethod
    def exact_unique_selectors(cls, value: list[str] | None, info) -> list[str] | None:
        if value is None:
            return None
        normalized = [item.strip().casefold() for item in value]
        pattern = _SOURCE if info.field_name == "source_instances" else _SEGMENT
        if any(pattern.fullmatch(item) is None for item in normalized):
            raise ValueError("selectors must be exact identities without wildcards")
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate selectors")
        return normalized

    @model_validator(mode="after")
    def treatment_parameters(self) -> Self:
        if (self.mode == "lossy") != (self.probability is not None):
            raise ValueError("probability is required only for lossy visibility")
        if (self.mode == "delayed") != (self.delay_us is not None):
            raise ValueError("delay_us is required only for delayed visibility")
        if self.hosts is not None and self.source_instances is not None:
            raise ValueError("select hosts or source_instances, not both")
        if self.mode == "missing_endpoint" and self.hosts is None and self.source_instances is None:
            raise ValueError("missing_endpoint requires explicit hosts or source_instances")
        return self


def _expand_formats(names: list[str]) -> set[str]:
    result: set[str] = set()
    for raw in names:
        if not isinstance(raw, str):
            raise ValueError("source formats must be strings")
        name = raw.strip().casefold()
        if name == "windows":
            result.update(("windows_event_sysmon", "windows_event_security"))
        elif name == "zeek":
            result.update(_ZEEK)
        elif name in _HOST_FORMATS or name in _SENSOR_FORMATS:
            result.add(name)
        else:
            raise ValueError(f"unknown pinned source format: {raw}")
    return result


def _owner(raw: str) -> str:
    if not isinstance(raw, str) or not _SEGMENT.fullmatch(raw.strip().casefold()):
        raise ValueError("source owners must be exact names")
    return raw.strip().casefold()


def _platform(os_name: str) -> str:
    name = os_name.strip().casefold()
    if "windows" in name:
        return "windows"
    if any(marker in name for marker in ("linux", "ubuntu", "centos", "debian", "rhel", "red hat")):
        return "linux"
    return "other"


def _deployed_sources(scenario: dict) -> tuple[set[str], set[str]]:
    """Resolve exact sources with the pinned compiler's output and owner filters."""
    formats = _expand_formats(
        [entry["format"] for entry in scenario.get("output", {}).get("logs", [])]
    )
    environment = scenario.get("environment", {})
    sources: set[str] = set()
    hosts: set[str] = set()
    for system in environment.get("systems", []):
        owner = _owner(system["hostname"])
        if owner in hosts:
            raise ValueError(f"duplicate host identity: {owner}")
        hosts.add(owner)
        platform = _platform(system["os"])
        roles = {role.strip().casefold().replace("_", "-") for role in system.get("roles", [])}
        for name in formats & _HOST_FORMATS.keys():
            family, platforms, role = _HOST_FORMATS[name]
            if platform in platforms and (role is None or role in roles):
                sources.add(f"{family}:{owner}")
    sensor_names: set[str] = set()
    for sensor in (environment.get("network") or {}).get("sensors", []):
        owner = _owner(sensor["name"])
        if owner in sensor_names:
            raise ValueError(f"duplicate sensor identity: {owner}")
        sensor_names.add(owner)
        sensor_type = sensor.get("type", "network").strip().casefold().replace("_", "-")
        for name in _expand_formats(sensor.get("log_formats", ["zeek"])):
            if name not in _SENSOR_FORMATS or _SENSOR_FORMATS[name][1] != sensor_type:
                raise ValueError(f"source format {name} cannot deploy on sensor {owner}")
            if name in formats:
                sources.add(f"{_SENSOR_FORMATS[name][0]}:{owner}")
    return sources, hosts


def apply_visibility(scenario: dict, settings: VisibilitySettings) -> dict:
    """Return an independent scenario with collection-only changes.

    Preserve unrelated overrides and allow identical overlapping values. Reject
    differing values on the same property; replacing an entire batching policy is
    a conflict even if only one nested field differs. No authored action, role,
    intent, or per-record availability metadata is changed.
    """
    # Revalidate because Pydantic's frozen model does not freeze nested lists.
    settings = VisibilitySettings.model_validate(settings.model_dump())
    result = deepcopy(scenario)
    sources, hosts = _deployed_sources(result)
    selected = set(settings.source_instances) if settings.source_instances is not None else sources
    if settings.hosts is not None:
        unknown_hosts = set(settings.hosts) - hosts
        if unknown_hosts:
            raise ValueError(f"unknown hosts: {sorted(unknown_hosts)}")
        selected = {
            source
            for source in sources
            if source.split(":")[1] in settings.hosts
            and source.split(":")[0] not in {"zeek", "ids", "asa"}
        }
    if selected - sources:
        raise ValueError(f"unknown or undeployed source instances: {sorted(selected - sources)}")
    if settings.mode == "missing_endpoint":
        if any(
            source.split(":")[0] not in {"sysmon", "windows_security"}
            for source in (settings.source_instances or [])
        ):
            raise ValueError("missing_endpoint selects Windows endpoint sources only")
        selected_hosts = set(settings.hosts or [source.split(":")[1] for source in selected])
        selected = {
            f"{family}:{host}"
            for host in selected_hosts
            for family in ("sysmon", "windows_security")
        }
        if selected - sources:
            raise ValueError("missing_endpoint requires both Windows endpoint sources deployed")

    environment = result.get("environment", {})
    existing = environment.get("observation_overrides", [])
    indexed = {}
    for override in existing:
        source = override.get("source_instance", "")
        if not isinstance(source, str) or _SOURCE.fullmatch(source.strip().casefold()) is None:
            raise ValueError("observation override requires an exact source_instance")
        source = source.strip().casefold()
        if source not in sources:
            raise ValueError(f"unknown or undeployed override source: {source}")
        if source in indexed:
            raise ValueError(f"duplicate observation override source: {source}")
        indexed[source] = override
    if settings.mode == "complete":
        return result
    if not selected:
        raise ValueError("visibility treatment has no deployed source instances")
    match settings.mode:
        case "lossy":
            patch = {"missingness": settings.probability}
        case "delayed":
            patch = {
                "batching": {"enabled": True, "interval_us": settings.delay_us, "max_records": 0}
            }
        case "missing_endpoint":
            patch = {"enabled": False}
    for source in sorted(selected):
        if source not in indexed:
            override = {"source_instance": source}
            indexed[source] = override
            existing.append(override)
        override = indexed[source]
        for key, value in patch.items():
            if key in override and override[key] != value:
                raise ValueError(f"visibility override conflict for {source}: {key}")
            override[key] = deepcopy(value)
    environment["observation_overrides"] = existing
    return result
