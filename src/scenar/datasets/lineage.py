"""Restricted dataset lineage and conservative, explicit holdout validation."""

import hashlib
import json
from datetime import timedelta, timezone
from pathlib import Path
from typing import Literal

from pydantic import Field

from ..bundle import Model
from ..io import canonical, digest
from ..lineage import Cohort, check_partitions
from ..replay import verify_bundle
from .audit import collection_window
from .matrix import _capture_digest, load_dataset


class CaseLineage(Model):
    case_id: str
    capture: str | None
    family: str
    environment: str
    time_blocks: list[str]
    variant: str
    seed: int = Field(strict=True)
    visibility: str
    related_cases: list[str] = Field(default_factory=list)


class DatasetLineage(Model):
    schema_id: Literal["scenar/dataset-lineage/v1"] = Field(
        default="scenar/dataset-lineage/v1", alias="schema"
    )
    manifest_sha256: str
    parent_sha256: str | None
    cases: list[CaseLineage]
    restricted: Literal[True] = True


def dataset_lineage(run: Path) -> DatasetLineage:
    manifest = verify_bundle(run)
    plan = load_dataset(run)
    cases = []
    for case in plan.cases:
        document = json.loads((run / case.scenario).read_bytes())["evidenceforge"]
        environment = dict(document["environment"])
        environment.pop("observation_overrides", None)
        start, end = collection_window(document)
        start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
        if end <= start:
            raise ValueError("Invalid lineage time window")
        day, last = start.date(), (end - timedelta(microseconds=1)).date()
        days = []
        while day <= last:
            days.append(day.isoformat())
            day += timedelta(days=1)
        native = run / "private/attempts" / case.id / "private/native"
        capture = _capture_digest(native) if native.exists() else None
        recorded = next((c for c in manifest.captures if c.id == case.id), None)
        if recorded is None or (capture is not None and recorded.source_sha256 != capture):
            raise ValueError("Dataset capture lineage differs from manifest")
        cases.append(
            CaseLineage(
                case_id=case.id,
                capture=capture,
                family=case.family,
                environment=hashlib.sha256(canonical(environment)).hexdigest(),
                time_blocks=days,
                variant=case.variant,
                seed=case.seed,
                visibility=plan.spec.visibility[case.visibility_index].mode,
            )
        )
    for row in cases:
        row.related_cases = [
            other.case_id
            for other in cases
            if other.case_id != row.case_id
            and (
                (row.capture is not None and row.capture == other.capture)
                or (row.family, row.environment, row.seed)
                == (other.family, other.environment, other.seed)
            )
        ]
    return DatasetLineage(
        manifest_sha256=digest(run / "manifest.json"),
        parent_sha256=manifest.parent_sha256,
        cases=cases,
    )


class SplitAssignment(Model):
    run: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    partition: Literal["development", "test"]
    exposed: bool = Field(strict=True)


class SplitSpec(Model):
    schema_id: Literal["scenar/dataset-splits/v1"] = Field(alias="schema")
    assignments: list[SplitAssignment] = Field(min_length=1)


def validate_splits(value: dict) -> dict:
    spec = SplitSpec.model_validate(value)
    by_run = {}
    seen = set()
    cohorts = []
    for assignment in spec.assignments:
        run = Path(assignment.run).resolve()
        identity = (run, assignment.case_id)
        if identity in seen:
            raise ValueError("Duplicate split assignment")
        seen.add(identity)
        by_run.setdefault(run, []).append(assignment)
    for run, assignments in by_run.items():
        lineage = dataset_lineage(run)
        cases = {c.case_id: c for c in lineage.cases}
        if set(cases) != {a.case_id for a in assignments}:
            raise ValueError("Split assignments must be complete for each supplied dataset")
        for assignment in assignments:
            row = cases[assignment.case_id]
            if row.capture is None:
                raise ValueError("Cannot assign an ungenerated capture to a split")
            for block in row.time_blocks:
                cohorts.append(
                    Cohort(
                        capture=row.capture,
                        family=row.family,
                        environment=row.environment,
                        time_block=block,
                        partition=assignment.partition,
                        exposed=assignment.exposed,
                    )
                )
    check_partitions(cohorts)
    return {
        "schema": "scenar/dataset-split-check/v1",
        "passed": True,
        "cases": len(spec.assignments),
        "datasets": len(by_run),
        "policy": "disjoint capture, family, environment and UTC calendar days",
    }
