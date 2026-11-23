"""Shared Python/Nickel authoring metadata, separate from the Forge scenario."""

import copy
import re
from typing import Literal, Self

from pydantic import Field, JsonValue, model_validator

from .attack import Catalog, Domain, Model, TechniqueSelection
from .background import BackgroundActivity, apply_background
from .truth import GroundTruth


class AttackBinding(TechniqueSelection):
    record_id: str = Field(min_length=1)


class AttackSettings(Model):
    domain: Domain = "enterprise-attack"
    release: str | None = None
    allow_retired: bool = Field(default=False, strict=True)
    mappings: list[AttackBinding] = Field(default_factory=list)


class AttackContext(Model):
    domain: Domain
    release: str
    catalog_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    mappings: list[AttackBinding]
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique(self) -> Self:
        keys = [(m.record_id, m.technique) for m in self.mappings]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate ATT&CK mapping")
        return self


class ScenarioDocument(Model):
    schema_id: Literal["scenar/scenario/v1"] = Field(default="scenar/scenario/v1", alias="schema")
    evidenceforge: dict[str, JsonValue]
    attack: AttackSettings = Field(default_factory=AttackSettings)
    ground_truth: GroundTruth = Field(default_factory=GroundTruth)
    background: BackgroundActivity | None = None


def authored_events(scenario: dict) -> dict[str, dict]:
    result = {}
    for section in ("storyline", "red_herrings"):
        steps = scenario.get(section) or []
        if not isinstance(steps, list):
            raise ValueError("Scenario sections must be lists or null")
        for step in steps:
            if not isinstance(step, dict):
                raise ValueError("Scenario steps must be records")
            if not isinstance(step.get("events", []), list):
                raise ValueError("Step events must be a list")
            for index, event in enumerate(step.get("events", [])):
                if not isinstance(event, dict):
                    raise ValueError("Scenario events must be records")
                if not isinstance(step.get("id"), str) or not step["id"]:
                    raise ValueError("ATT&CK-aware scenario events require explicit step IDs")
                id = f"{step['id']}#{index}"
                if id in result:
                    raise ValueError(f"Duplicate authored event ID: {id}")
                result[id] = event
    return result


def resolve_attack(scenario: dict, settings: AttackSettings, catalog: Catalog) -> AttackContext:
    if settings.domain != catalog.domain or (
        settings.release and settings.release != catalog.release
    ):
        raise ValueError("Scenario ATT&CK domain/release differs from pinned catalogue")
    events = authored_events(scenario)
    mappings = {(m.record_id, m.technique): m for m in settings.mappings}
    if len(mappings) != len(settings.mappings):
        raise ValueError("Duplicate ATT&CK mapping")
    for record_id, event in events.items():
        label = event.get("technique")
        if label is None:
            continue
        match = (
            re.fullmatch(r"(T[0-9]{4}(?:\.[0-9]{3})?)(?:\s+-\s+.+)?", label)
            if isinstance(label, str)
            else None
        )
        if not match:
            raise ValueError(f"Malformed ATT&CK technique tag: {label!r}")
        technique = match.group(1)
        mappings.setdefault(
            (record_id, technique), AttackBinding(record_id=record_id, technique=technique)
        )
    warnings = []
    for binding in mappings.values():
        if binding.record_id not in events:
            raise ValueError(f"Mapping references unknown authored event: {binding.record_id}")
        technique = catalog.resolve(binding, allow_retired=settings.allow_retired)
        if (
            technique.revoked
            or technique.deprecated
            or (
                technique.parent
                and (
                    catalog.techniques[technique.parent].revoked
                    or catalog.techniques[technique.parent].deprecated
                )
            )
        ):
            warnings.append(f"Historical retired mapping: {technique.id}")
    return AttackContext(
        domain=catalog.domain,
        release=catalog.release,
        catalog_sha256=catalog.sha256,
        source_sha256=catalog.source_sha256,
        mappings=list(mappings.values()),
        warnings=sorted(set(warnings)),
    )


def compile_document(
    document: ScenarioDocument, catalog: Catalog, *, noise_only: bool = False
) -> tuple[dict, AttackContext]:
    scenario = copy.deepcopy(document.evidenceforge)
    if not isinstance(scenario.get("name"), str):
        raise ValueError("Scenario must have a name")
    context = resolve_attack(scenario, document.attack, catalog)
    if set(document.ground_truth.labels) - authored_events(scenario).keys():
        raise ValueError("Intent labels reference unknown authored events")
    if document.ground_truth.episodes:
        raise ValueError("Episode labels require a frozen pack membership contract")
    if document.background:
        scenario = apply_background(scenario, document.background, noise_only=noise_only)
    elif noise_only:
        raise ValueError("Noise-only generation requires a background profile")
    if noise_only:
        context = resolve_attack(
            scenario,
            AttackSettings(
                domain=document.attack.domain,
                release=document.attack.release,
                allow_retired=document.attack.allow_retired,
            ),
            catalog,
        )
    return scenario, context


def nickel_attack_settings(compiled: dict) -> dict:
    """Carry procedure tactics and benign look-alike mappings across Nickel compilation."""
    raw = copy.deepcopy(compiled.get("scenar", {}))
    settings = AttackSettings.model_validate(raw.get("attack", {}))
    inferred = {}
    for procedure in compiled.get("procedure_metadata", []):
        if not procedure["enabled"]:
            continue
        technique = procedure["technique"]
        positions = list(enumerate(procedure.get("opening_events", []))) + [
            (i + procedure["event_offset"], e) for i, e in enumerate(procedure["events"])
        ]
        for index, event in positions:
            label = event.get("technique", technique["id"])
            match = re.fullmatch(r"(T[0-9]{4}(?:\.[0-9]{3})?)(?:\s+-\s+.+)?", label)
            if not match:
                raise ValueError(f"Malformed procedure ATT&CK label: {label}")
            id = match.group(1)
            mapping = AttackBinding(
                record_id=f"{procedure['id']}#{index}",
                technique=id,
                tactic=technique.get("tactic") if id == technique["id"] else None,
            )
            inferred[mapping.record_id, mapping.technique] = mapping
    explicit = set()
    for mapping in settings.mappings:
        key = mapping.record_id, mapping.technique
        if key in explicit:
            raise ValueError("Duplicate explicit ATT&CK mapping")
        explicit.add(key)
        previous = inferred.get(key)
        if previous and previous.tactic:
            if mapping.tactic and mapping.tactic != previous.tactic:
                raise ValueError("Conflicting declared procedure tactic")
            mapping = mapping.model_copy(update={"tactic": previous.tactic})
        inferred[key] = mapping
    settings.mappings = list(inferred.values())
    raw["attack"] = settings.model_dump(mode="json")
    return raw


def authored_cardinality(scenario: dict) -> dict[str, int]:
    counts = {}
    for id in authored_events(scenario):
        sid = id.rpartition("#")[0]
        counts[sid] = counts.get(sid, 0) + 1
    return counts
