"""Versioned run and artifact contracts. Manifests are restricted metadata."""

from pathlib import Path
from typing import Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
    model_validator,
)

from .backend import BackendIdentity
from .background import BackgroundActivity
from .evaluation.models import Approval, Contract
from .io import safe_path
from .scenario import AttackContext
from .truth import GroundTruth


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class QualityReport(BaseModel):
    # Upstream may add metrics without changing the mandatory verdict.
    model_config = ConfigDict(extra="ignore")
    acceptance_passed: bool = Field(strict=True)
    overall_score: float | None = Field(default=None, allow_inf_nan=False)
    flags: list[str] = Field(default_factory=list)


class Qualification(Model):
    native_passed: bool = Field(strict=True)
    backend_passed: bool = Field(strict=True)
    reasons: list[str] = Field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return self.native_passed and self.backend_passed


class Artifact(Model):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0, strict=True)

    @field_validator("path")
    @classmethod
    def confined(cls, value: str) -> str:
        safe_path(Path("/__scenar_artifacts__"), value)
        return value


class Capture(Model):
    id: str
    qualified: bool = Field(strict=True)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    family: str


class View(Model):
    id: str
    capture_id: str
    context: Literal["available", "withheld", "late"]


class Evaluation(Model):
    id: str
    view_id: str
    policy: str
    budget: int = Field(strict=True, ge=0)
    evaluator_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class BundleManifest(Model):
    schema_id: Literal["scenar/bundle/v1"] = Field(default="scenar/bundle/v1", alias="schema")
    bundle_id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    provenance: Literal["synthetic", "imported", "transformed"] = "synthetic"
    parent_sha256: str | None = None
    captures: list[Capture] = Field(default_factory=list)
    views: list[View] = Field(default_factory=list)
    evaluations: list[Evaluation] = Field(default_factory=list)
    files: list[Artifact]

    @model_validator(mode="after")
    def unique(self) -> Self:
        for ids in (
            [f.path for f in self.files],
            [c.id for c in self.captures],
            [v.id for v in self.views],
            [e.id for e in self.evaluations],
        ):
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate artifact or capture identity")
        if not {v.capture_id for v in self.views} <= {c.id for c in self.captures}:
            raise ValueError("Unknown view capture")
        if not {e.view_id for e in self.evaluations} <= {v.id for v in self.views}:
            raise ValueError("Unknown evaluation view")
        return self

    @property
    def qualified(self) -> bool:
        return bool(self.captures) and all(c.qualified for c in self.captures)


class Audit(Model):
    source_ip: str
    as_of: AwareDatetime
    max_source_time_skew_seconds: int = Field(ge=0, strict=True)
    case_id: str
    target_host: str
    actor: str
    archive_path: str
    required_commands: list[str]
    required_record_ids: list[str]


class Case(Model):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    family: str
    seed: int = Field(strict=True, ge=0)
    scenario: str
    scenario_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    audits: list[Audit] = Field(min_length=1)
    approvals: list[Approval]
    private: Contract
    attack: AttackContext | None = None
    ground_truth: GroundTruth = Field(default_factory=GroundTruth)
    background: BackgroundActivity | None = None

    @field_validator("scenario")
    @classmethod
    def confined(cls, value: str) -> str:
        safe_path(Path("/__scenar_protocol__"), value)
        return value


class RunProtocol(Model):
    schema_id: Literal["scenar/protocol/v1"] = Field(default="scenar/protocol/v1", alias="schema")
    pack: Literal["investigation-episodes"] = "investigation-episodes"
    backend: BackendIdentity | None
    cases: list[Case] = Field(min_length=1)
    start: AwareDatetime
    as_of: AwareDatetime
    budgets: list[StrictInt] = Field(default_factory=lambda: [0, 4, 16, 64])
    policies: list[Literal["alert_only", "context", "unique_chain", "entity_fusion"]] = Field(
        default_factory=lambda: ["alert_only", "context", "unique_chain", "entity_fusion"]
    )
    contexts: list[Literal["available", "withheld", "late"]] = Field(
        default_factory=lambda: ["available", "withheld", "late"]
    )
    stage_timeout_seconds: int = Field(default=300, ge=1, strict=True)
    sources: dict[str, str]
    origin: Literal["prepared", "legacy-replay", "replay"] = "prepared"
    catalog_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.as_of <= self.start:
            raise ValueError("Empty run interval")
        for items in ([c.id for c in self.cases], self.budgets, self.policies, self.contexts):
            if not items or len(items) != len(set(items)):
                raise ValueError("Empty or duplicate planned matrix dimension")
        if any(type(b) is not int or b < 0 for b in self.budgets):
            raise ValueError("Invalid query budget")
        if "available" not in self.contexts:
            raise ValueError("The initial public feed requires the available snapshot")
        return self


class Stage(Model):
    stage: str
    args: list[str]
    exit: int = Field(strict=True)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)


class CaptureResult(Model):
    id: str
    eligible: bool = Field(default=False, strict=True)
    native_eligible: bool = Field(default=False, strict=True)
    stages: list[Stage] = Field(default_factory=list)
    error: str | None = None
