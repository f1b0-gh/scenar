"""Separate public observations/permissions from private episode adjudication."""

from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

Status = Literal["benign", "actionable", "unknown"]
Action = Literal["inventory", "archive"]
Policy = Literal[
    "alert_only",
    "context",
    "unique_chain",
    "entity_fusion",
    "proof_guard",
    "proof_adaptive",
    "history_risk",
    "followup_cautious",
    "followup_paged",
    "followup_ranked",
    "followup_fused",
    "followup_contextual",
]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Record(Model):
    id: str = Field(min_length=1)
    source: Literal["sysmon", "security", "zeek_conn"]
    event_id: int
    host: str = Field(min_length=1)
    time: AwareDatetime
    data: dict[str, str]


class Grant(Model):
    action: Action
    input_path: str = Field(min_length=1)
    output_path: str | None = None

    @model_validator(mode="after")
    def archive_destination(self) -> Self:
        if (self.action == "archive") != bool(self.output_path):
            raise ValueError("Only archive grants require an exact output_path")
        return self


class Approval(Model):
    id: str = Field(min_length=1)
    revision: int = Field(ge=1, strict=True)
    available_at: AwareDatetime
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    account: str = Field(min_length=1)
    hosts: list[str] = Field(min_length=1)
    grants: list[Grant]

    @model_validator(mode="after")
    def window(self) -> Self:
        if self.valid_until <= self.valid_from:
            raise ValueError("Empty approval validity interval")
        return self


class Snapshot(Model):
    start: AwareDatetime
    as_of: AwareDatetime
    records: list[Record]
    approvals: list[Approval] = Field(default_factory=list)

    @model_validator(mode="after")
    def identities(self) -> Self:
        if self.start >= self.as_of:
            raise ValueError("Empty snapshot interval")
        ids = [r.id for r in self.records]
        revisions = [(r.id, r.revision) for r in self.approvals]
        if len(ids) != len(set(ids)) or len(revisions) != len(set(revisions)):
            raise ValueError("Duplicate observation or approval revision")
        return self


class Candidate(Model):
    record: Record
    action: Action
    input_path: str
    output_path: str | None = None


class Member(Model):
    authored_record_id: str
    episode_ids: list[str]
    role: Literal["action", "context", "evidence"]


class Contract(Model):
    episodes: dict[str, Status]
    members: list[Member]

    @model_validator(mode="after")
    def references(self) -> Self:
        seen: set[str] = set()
        for member in self.members:
            if member.authored_record_id in seen:
                raise ValueError("Duplicate authored member")
            seen.add(member.authored_record_id)
            if len(set(member.episode_ids)) != len(member.episode_ids):
                raise ValueError("Duplicate episode membership")
            if set(member.episode_ids) - self.episodes.keys():
                raise ValueError("Unknown episode")
        return self


class Oracle(Model):
    episodes: dict[str, Status]
    actions: dict[str, list[str]]
    useful_evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def references(self) -> Self:
        for members in self.actions.values():
            if set(members) - self.episodes.keys() or len(members) != len(set(members)):
                raise ValueError("Unknown or duplicate private episode")
        return self


class Receipt(Model):
    kind: Literal[
        "authorization", "lineage", "observations", "history", "survey", "network", "destinations"
    ]
    candidate: str
    returned_ids: list[str]
    response_bytes: int = Field(ge=0)
    complete: bool


class Result(Model):
    policy: Policy
    budget: int = Field(ge=0, strict=True)
    candidates: list[str]
    decisions: dict[str, Literal["clear", "escalate", "unresolved"]]
    groups: list[list[str]]
    trace: list[Receipt]
    scanned_records: int = Field(ge=0)
    scanned_bytes: int = Field(ge=0)

    @property
    def queries(self) -> int:
        return len(self.trace)

    @model_validator(mode="after")
    def partition(self) -> Self:
        flat = [i for g in self.groups for i in g]
        if (
            len(self.candidates) != len(set(self.candidates))
            or set(self.decisions) != set(self.candidates)
            or len(flat) != len(set(flat))
            or set(flat) != set(self.candidates)
            or any(not g for g in self.groups)
            or len(self.trace) > self.budget
        ):
            raise ValueError("Incomplete candidate partition or query budget exceeded")
        if any(len(g) > 1 and any(self.decisions[i] != "escalate" for i in g) for g in self.groups):
            raise ValueError("Only escalated members can form a delivered group")
        return self
