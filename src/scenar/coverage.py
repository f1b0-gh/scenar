"""ATT&CK coverage separates authored mappings, qualified observations and detector reports."""

from typing import Literal

from pydantic import Field

from .attack import Catalog, Model
from .scenario import AttackContext


class Detection(Model):
    case_id: str
    technique: str = Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")
    observation_id: str = Field(min_length=1)


class Detections(Model):
    schema_version: Literal["scenar/attack-detections/v1"] = "scenar/attack-detections/v1"
    detector: str = Field(min_length=1)
    detections: list[Detection]


def coverage(
    context: AttackContext,
    catalog: Catalog,
    *,
    observations: dict[str, list[str]] | None = None,
    detected: set[tuple[str, str]] | None = None,
) -> dict:
    if (
        context.catalog_sha256 != catalog.sha256
        or context.domain != catalog.domain
        or context.release != catalog.release
    ):
        raise ValueError("Coverage catalogue differs from frozen mapping")
    observations = observations or {}
    detected = detected or set()
    valid = {
        (m.technique, id) for m in context.mappings for id in observations.get(m.record_id, [])
    }
    if detected - valid:
        raise ValueError("Detection references an unqualified or unmapped observation")
    rows = []
    for id in sorted({m.technique for m in context.mappings}):
        mappings = [m for m in context.mappings if m.technique == id]
        native = {n for m in mappings for n in observations.get(m.record_id, [])}
        rows.append(
            {
                "technique": id,
                "name": catalog.techniques[id].name,
                "authored": len(mappings),
                "observed": len(native),
                "detected": len({n for t, n in detected if t == id}),
                "observation_ids": sorted(native),
                "detected_observation_ids": sorted(n for t, n in detected if t == id),
            }
        )
    return {
        "schema": "scenar/attack-coverage/v1",
        "domain": context.domain,
        "release": context.release,
        "catalog_sha256": catalog.sha256,
        "source_sha256": catalog.source_sha256,
        "techniques": rows,
        "warnings": context.warnings,
        "scope": "Observed counts require qualified native references; detected counts are explicit detector reports, not operational certification",
    }


def navigator(
    report: dict, stage: Literal["authored", "observed", "detected"] = "authored"
) -> dict:
    if stage not in ("authored", "observed", "detected"):
        raise ValueError("Unknown coverage stage")
    return {
        "name": f"Scenar {stage} coverage",
        "description": report["scope"],
        "domain": report["domain"],
        "versions": {"layer": "4.5", "attack": report["release"]},
        "metadata": [
            {"name": "coverage_stage", "value": stage},
            {"name": "catalog_sha256", "value": report["catalog_sha256"]},
        ],
        "techniques": [
            {
                "techniqueID": r["technique"],
                "score": r[stage],
                "comment": f"{stage} count; no maliciousness inference",
            }
            for r in report["techniques"]
            if r[stage] > 0
        ],
    }
