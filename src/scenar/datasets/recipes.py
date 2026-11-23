"""Deterministic private authoring recipes, independent of detector decisions.

These recipes describe synthetic actions, never execute their command lines. A
paired source-host intervention is evidence of different provenance, not proof
of maliciousness. Baseline records without explicit membership remain unknown.
"""

from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, model_validator

from scenar.scenario import ScenarioDocument
from scenar.truth import GroundTruth, IntentLabel

from .audit import EffectExpectation, EffectRelationship

Family = Literal["inventory_archive", "remote_access", "persistence", "credential_access", "c2"]
Variant = Literal["normal", "benign", "malicious", "mixed", "ambiguous"]
Size = Literal["small", "medium", "large"]
C2Pattern = Literal["periodic", "burst", "sparse", "rotating"]
FAMILIES = ("inventory_archive", "remote_access", "persistence", "credential_access", "c2")
VARIANTS = ("normal", "benign", "malicious", "mixed", "ambiguous")
SIZES = ("small", "medium", "large")
C2_PATTERNS = ("periodic", "burst", "sparse", "rotating")
SIZE_COUNTS = {"small": (3, 2), "medium": (10, 8), "large": (30, 28)}
CMD = r"C:\Windows\System32\cmd.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ARCHIVE_COMMAND = (
    r"powershell.exe -NoProfile -Command Compress-Archive -Path C:\Records "
    r"-DestinationPath C:\Windows\Temp\records.zip -Force"
)


class Recipe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    document: ScenarioDocument
    expectations: list[EffectExpectation]
    metadata: dict[str, JsonValue]


class _Options(BaseModel):
    model_config = ConfigDict(extra="forbid")
    family: Family
    variant: Variant
    size: Size
    start: AwareDatetime
    duration_minutes: int = Field(default=60, strict=True, ge=10, le=10080)
    routine_cycles: int = Field(default=2, strict=True, ge=1, le=100)
    c2_pattern: C2Pattern = "periodic"

    @model_validator(mode="after")
    def fit_schedule(self):
        if self.duration_minutes * 60 < self.routine_cycles * 150:
            raise ValueError("Routine cycles need at least 150 seconds including native jitter")
        return self


def _environment(size: Size) -> dict[str, JsonValue]:
    hosts, user_count = SIZE_COUNTS[size]
    endpoint_count = hosts - 2
    users = [
        {
            "username": f"operator{i:02}",
            "full_name": f"Office Operator {i:02}",
            "email": f"operator{i:02}@office.example",
            "persona": "administrator" if i == 1 else "office_worker",
            "primary_system": f"WS-{min(i, endpoint_count):02}",
            "groups": ["it-admins"] if i == 1 else ["staff"],
            "enabled": True,
            "browsing_intensity": "light",
        }
        for i in range(1, user_count + 1)
    ]
    systems = [
        {
            "hostname": "DC-01",
            "ip": "10.44.20.10",
            "os": "Windows Server 2022",
            "type": "domain_controller",
            "services": ["kerberos", "ldap", "dns", "windows-dhcp-server"],
            "roles": ["domain_controller", "dns_server", "dhcp_server"],
        },
        {
            "hostname": "FILE-01",
            "ip": "10.44.20.20",
            "os": "Windows Server 2022",
            "type": "server",
            "services": ["smb", "dns-client"],
            "roles": ["file_server"],
        },
    ] + [
        {
            "hostname": f"WS-{i:02}",
            "ip": f"10.44.10.{20 + i}",
            "os": "Windows 11 Enterprise",
            "type": "workstation",
            "assigned_user": f"operator{i:02}",
            "services": ["dns-client"],
        }
        for i in range(1, endpoint_count + 1)
    ]
    return {
        "description": "Office environment with directory services, file storage and endpoints",
        "domain": "office.example",
        "timezone": {"default": "UTC"},
        "users": users,
        "systems": systems,
        "service_accounts": ["svc-backup"],
        "groups": [
            {"name": "it-admins", "members": ["operator01"]},
            {"name": "staff", "members": [u["username"] for u in users[1:]]},
        ],
        "network": {
            "segments": [
                {
                    "name": "endpoints",
                    "cidr": "10.44.10.0/24",
                    "exposure": "internal",
                    "systems": [s["hostname"] for s in systems[2:]],
                },
                {
                    "name": "servers",
                    "cidr": "10.44.20.0/24",
                    "exposure": "internal",
                    "systems": ["DC-01", "FILE-01"],
                },
            ],
            "sensors": [
                {
                    "type": "network",
                    "name": "core-span",
                    "hostname": "SENSOR-01",
                    "monitoring_segments": ["endpoints", "servers"],
                    "direction": "bidirectional",
                    "placement": "span",
                    "log_formats": ["zeek"],
                }
            ],
        },
    }


class _Builder:
    def __init__(self, options: _Options):
        self.options = options
        self.steps: list[dict] = []
        self.labels: dict[str, IntentLabel] = {}
        self.expectations: list[EffectExpectation] = []
        self.routines: list[dict] = []

    def instant(self, seconds: int) -> str:
        return (self.options.start.astimezone(UTC) + timedelta(seconds=seconds)).isoformat()

    def add(
        self,
        id: str,
        seconds: int,
        event: dict,
        *,
        actor="operator01",
        host="FILE-01",
        intent="benign",
        rationale="Authorized scheduled office work",
    ) -> str:
        self.steps.append(
            {
                "id": id,
                "time": f"+{seconds}s",
                "actor": actor,
                "system": host,
                "activity": "Office workflow",
                "events": [event],
            }
        )
        authored_id = f"{id}#0"
        self.labels[authored_id] = IntentLabel(intent=intent, rationale=rationale)
        return authored_id

    def expect(
        self,
        id: str,
        authored_id: str,
        seconds: int,
        source: str,
        event_id: int | str,
        fields: dict[str, str],
        *,
        host="FILE-01",
        relationship=None,
    ):
        self.expectations.append(
            EffectExpectation(
                id=id,
                authored_event_id=authored_id,
                source=source,
                event_id=event_id,
                host=host if source == "zeek" else f"{host}.office.example",
                time=self.instant(seconds),
                tolerance_seconds=35,
                fields=fields,
                relationship=relationship,
            )
        )

    def process(
        self,
        id: str,
        seconds: int,
        image: str,
        command: str,
        *,
        parent=None,
        actor="operator01",
        host="FILE-01",
        intent="benign",
        rationale="Authorized scheduled office work",
    ):
        event = {
            "type": "process",
            "process_name": image,
            "command_line": command,
            "process_ref": id,
            "supplementary": "none",
        }
        if parent:
            event["parent_ref"] = parent
        authored_id = self.add(
            id, seconds, event, actor=actor, host=host, intent=intent, rationale=rationale
        )
        relationship = (
            EffectRelationship(
                expectation_id=parent,
                field="ParentProcessGuid",
                target_field="ProcessGuid",
                kind="process_guid",
            )
            if parent
            else None
        )
        self.expect(
            id,
            authored_id,
            seconds,
            "sysmon",
            1,
            {"Image": image, "CommandLine": command, "User": f"OFFICE\\{actor}"},
            host=host,
            relationship=relationship,
        )
        return authored_id

    def scheduled_routines(self):
        total = self.options.duration_minutes * 60
        for cycle in range(self.options.routine_cycles):
            base = 45 + cycle * total // self.options.routine_cycles
            for offset, kind in enumerate(("session", "administration", "backup", "diagnostics")):
                seconds = base + offset * 20
                id = f"r{cycle:03}-{offset}"
                self.routines.append(
                    {"kind": kind, "time": self.instant(seconds), "authored_event_id": f"{id}#0"}
                )
                if kind == "session":
                    aid = self.add(
                        id,
                        seconds,
                        {"type": "logon", "logon_type": 3, "source_ip": "10.44.20.10"},
                        actor="operator02",
                        host="WS-01",
                    )
                    self.expect(
                        id,
                        aid,
                        seconds,
                        "security",
                        4624,
                        {
                            "TargetUserName": "operator02",
                            "TargetDomainName": "OFFICE",
                            "LogonType": "3",
                            "IpAddress": "10.44.20.10",
                        },
                        host="WS-01",
                    )
                elif kind == "administration":
                    self.process(
                        id, seconds, CMD, "cmd.exe /c systeminfo", actor="operator02", host="WS-01"
                    )
                elif kind == "backup":
                    aid = self.process(id, seconds, POWERSHELL, ARCHIVE_COMMAND, actor="svc-backup")
                    self.expect(
                        id + "-file",
                        aid,
                        seconds,
                        "sysmon",
                        11,
                        {"TargetFilename": r"C:\Windows\Temp\records.zip"},
                        relationship=EffectRelationship(
                            expectation_id=id, field="ProcessGuid", target_field="ProcessGuid"
                        ),
                    )
                else:
                    self.process(
                        id,
                        seconds,
                        POWERSHELL,
                        "powershell.exe -NoProfile -Command Get-Process | Sort-Object CPU -Descending",
                        actor="operator02",
                        host="WS-01",
                        rationale="Authorized unusual performance investigation",
                    )

    def focal(self, block: int, *, malicious: bool, intent: str):
        total = self.options.duration_minutes * 60
        base = total // 3 if block == 0 else 2 * total // 3
        prefix = f"w{block:02}"
        rationale = {
            "benign": "Authorized maintenance and diagnostics",
            "malicious": "Author-declared unauthorized use of the account and workflow",
            "unknown": "Authorization deliberately withheld; same authored observations as benign control",
        }[intent]
        provenance = "10.44.20.10" if malicious else "10.44.10.21"
        aid = self.add(
            prefix + "-0",
            base,
            {"type": "rdp_session", "source_ip": provenance},
            intent=intent,
            rationale=rationale,
        )
        self.expect(
            prefix + "-session",
            aid,
            base,
            "security",
            4624,
            {
                "TargetUserName": "operator01",
                "TargetDomainName": "OFFICE",
                "LogonType": "10",
                "IpAddress": provenance,
            },
        )
        shell = prefix + "-1"
        self.process(shell, base + 30, CMD, "cmd.exe", intent=intent, rationale=rationale)
        self.expectations[-1].relationship = EffectRelationship(
            expectation_id=prefix + "-session",
            field="LogonId",
            target_field="TargetLogonId",
            kind="logon_id",
        )
        common = {"intent": intent, "rationale": rationale}
        family = self.options.family
        if family == "inventory_archive":
            self.process(
                prefix + "-2",
                base + 60,
                CMD,
                r"cmd.exe /c dir C:\Records /s",
                parent=shell,
                **common,
            )
            id = prefix + "-3"
            aid = self.process(id, base + 90, POWERSHELL, ARCHIVE_COMMAND, parent=shell, **common)
            self.expect(
                id + "-file",
                aid,
                base + 90,
                "sysmon",
                11,
                {"TargetFilename": r"C:\Windows\Temp\records.zip"},
                relationship=EffectRelationship(
                    expectation_id=id, field="ProcessGuid", target_field="ProcessGuid"
                ),
            )
        elif family == "remote_access":
            self.process(
                prefix + "-2", base + 60, CMD, "cmd.exe /c hostname", parent=shell, **common
            )
        elif family == "persistence":
            aid = self.add(
                prefix + "-2",
                base + 60,
                {
                    "type": "scheduled_task_created",
                    "task_name": r"\Office\Inventory",
                    "task_content": r"C:\Windows\System32\cmd.exe /c dir C:\Records /s",
                },
                **common,
            )
            self.expect(
                prefix + "-task",
                aid,
                base + 60,
                "security",
                4698,
                {
                    "TaskName": r"\Office\Inventory",
                    "SubjectUserName": "operator01",
                    "SubjectDomainName": "OFFICE",
                },
                relationship=EffectRelationship(
                    expectation_id=prefix + "-session",
                    field="SubjectLogonId",
                    target_field="TargetLogonId",
                    kind="logon_id",
                ),
            )
            aid = self.add(
                prefix + "-3",
                base + 90,
                {
                    "type": "service_installed",
                    "service_name": "OfficeInventory",
                    "service_file_name": r"C:\Windows\System32\cmd.exe /c dir C:\Records /s",
                },
                **common,
            )
            self.expect(
                prefix + "-service",
                aid,
                base + 90,
                "security",
                4697,
                {
                    "ServiceName": "OfficeInventory",
                    "ServiceFileName": r"C:\Windows\System32\cmd.exe /c dir C:\Records /s",
                    "SubjectUserName": "operator01",
                    "SubjectDomainName": "OFFICE",
                },
                relationship=EffectRelationship(
                    expectation_id=prefix + "-session",
                    field="SubjectLogonId",
                    target_field="TargetLogonId",
                    kind="logon_id",
                ),
            )
        elif family == "credential_access":
            aid = self.add(
                prefix + "-2",
                base + 60,
                {"type": "process_access", "target_process": "lsass.exe", "access_mask": "0x1010"},
                **common,
            )
            self.expect(
                prefix + "-access",
                aid,
                base + 60,
                "sysmon",
                10,
                {"TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1010"},
                relationship=EffectRelationship(
                    expectation_id=shell, field="SourceProcessGUID", target_field="ProcessGuid"
                ),
            )
        else:
            self.beacons(prefix, base + 60, common)

    def beacons(self, prefix: str, base: int, common: dict):
        pattern = self.options.c2_pattern
        total = self.options.duration_minutes * 60
        count, interval, groups = {
            "periodic": (4, max(5, total // 120), 1),
            "burst": (4, 2, 3),
            "sparse": (2, max(10, total // 12), 1),
            "rotating": (2, 10, 3),
        }[pattern]
        for group in range(groups):
            seconds = base + group * 30
            ip = f"198.51.100.{40 + group if pattern == 'rotating' else 40}"
            aid = self.add(
                f"{prefix}-b{group}",
                seconds,
                {
                    "type": "beacon",
                    "dst_ip": ip,
                    "dst_port": 443,
                    "service": "ssl",
                    "interval": f"{interval}s",
                    "count": count,
                    "jitter": 0,
                },
                **common,
            )
            for tick in range(count):
                self.expect(
                    f"{prefix}-b{group}-t{tick}",
                    aid,
                    seconds + tick * interval,
                    "zeek",
                    "conn",
                    {
                        "id.orig_h": "10.44.20.20",
                        "id.resp_h": ip,
                        "id.resp_p": "443",
                        "proto": "tcp",
                    },
                    host="core-span",
                )


def build_recipe(
    family: Family,
    variant: Variant,
    size: Size,
    *,
    start: datetime,
    duration_minutes: int = 60,
    routine_cycles: int = 2,
    c2_pattern: C2Pattern = "periodic",
) -> Recipe:
    """Build a bounded workload; labels and recipe provenance are private metadata.

    ``ambiguous`` uses the exact benign Forge document, with unknown focal truth.
    Matching seeds across *different* documents do not promise equal baseline bytes.
    ``normal`` contains only explicitly labeled routines plus unindexed Forge baseline.
    """
    options = _Options(
        family=family,
        variant=variant,
        size=size,
        start=start,
        duration_minutes=duration_minutes,
        routine_cycles=routine_cycles,
        c2_pattern=c2_pattern,
    )
    builder = _Builder(options)
    builder.scheduled_routines()
    if variant != "normal":
        builder.focal(
            0,
            malicious=variant == "malicious",
            intent="unknown"
            if variant == "ambiguous"
            else "malicious"
            if variant == "malicious"
            else "benign",
        )
    if variant == "mixed":
        builder.focal(1, malicious=True, intent="malicious")
    builder.steps.sort(key=lambda step: (int(step["time"][1:-1]), step["id"]))
    scenario = {
        "version": "1.0",
        "name": "synthetic-workflow",
        "description": "Synthetic office workflow; commands are modeled, never executed",
        "environment": _environment(size),
        "personas": [
            {
                "name": "administrator",
                "description": "Office administration",
                "risk_profile": "low",
            },
            {
                "name": "office_worker",
                "description": "Office documents and communication",
                "risk_profile": "low",
            },
        ],
        "time_window": {
            "start": options.start.astimezone(UTC).isoformat(),
            "duration": f"{duration_minutes}m",
            "warmup": "1h",
        },
        "baseline_activity": {
            "description": "Office browsing, authentication and file activity",
            "intensity": "low",
            "variation": "low",
            "suspicious_noise": "low",
            "traffic_rates": {"web": "low", "user_activity": "low", "persona_connections": "low"},
        },
        "observation_profile": "complete",
        "storyline": builder.steps,
        "red_herrings": [],
        "output": {
            "logs": [
                {"format": format}
                for format in ("windows_event_sysmon", "windows_event_security", "zeek", "ecar")
            ],
            "destination": "generated/workflow",
            "compression": False,
        },
    }
    return Recipe(
        document=ScenarioDocument(
            evidenceforge=scenario,
            ground_truth=GroundTruth(mode="intent-aware", labels=builder.labels),
        ),
        expectations=builder.expectations,
        metadata={
            "family": family,
            "variant": variant,
            "size": size,
            "c2_pattern": c2_pattern if family == "c2" else None,
            "hosts": SIZE_COUNTS[size][0],
            "users": SIZE_COUNTS[size][1],
            "routines": builder.routines,
            "ambient_intent": "unknown_unindexed",
            "paired_intervention": "remote_session_source_host",
            "observation_equivalence": "benign_recipe_only" if variant == "ambiguous" else None,
            "limitations": [
                "Source provenance is not an authorization verdict",
                "C2 variants model separate connections, not persistent sessions",
                "Process access models memory access, not successful credential extraction",
                "Installation events do not prove later service or task execution",
                "Native audit must establish emitted effects independently",
            ],
        },
    )
