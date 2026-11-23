"""Offline, content-pinned ATT&CK technique/tactic catalogues and selections."""

import hashlib
import json
from importlib.resources import files as resources
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .io import canonical, digest, write_json

Domain = Literal["enterprise-attack", "mobile-attack", "ics-attack"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TechniqueSelection(Model):
    technique: str = Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")
    tactic: str | None = None
    platforms: list[str] = Field(default_factory=list)


class Technique(Model):
    id: str = Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")
    stix_id: str
    name: str
    modified: AwareDatetime
    object_version: str
    tactics: list[str]
    platforms: list[str]
    parent: str | None = None
    revoked: bool = Field(default=False, strict=True)
    deprecated: bool = Field(default=False, strict=True)
    marking_refs: list[str] = Field(default_factory=list)


class Tactic(Model):
    id: str = Field(pattern=r"^TA[0-9]{4}$")
    stix_id: str
    name: str
    shortname: str
    revoked: bool = Field(default=False, strict=True)
    deprecated: bool = Field(default=False, strict=True)


class Catalog(Model):
    schema_version: Literal["scenar/attack-catalog/v1"] = "scenar/attack-catalog/v1"
    domain: Domain
    release: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_url: str | None = None
    techniques: dict[str, Technique]
    tactics: dict[str, Tactic]
    # Preserve markings as data; importing a catalogue does not authorize disclosure.
    markings: list[dict] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if not self.techniques or not self.tactics:
            raise ValueError("Catalogue needs techniques and tactics for the selected domain")
        if len({t.id for t in self.tactics.values()}) != len(self.tactics) or len(
            {t.stix_id for t in self.tactics.values()}
        ) != len(self.tactics):
            raise ValueError("Duplicate tactic identity")
        if len({t.stix_id for t in self.techniques.values()}) != len(self.techniques):
            raise ValueError("Duplicate technique STIX identity")
        for key, t in self.techniques.items():
            if "." in key and not (t.revoked or t.deprecated) and t.parent is None:
                raise ValueError(f"Active subtechnique lacks parent: {key}")
            if key != t.id or len(t.tactics) != len(set(t.tactics)):
                raise ValueError("Invalid technique identity or duplicate tactic")
            if set(t.tactics) - self.tactics.keys():
                raise ValueError(f"Unknown tactic on {key}")
            if t.parent is not None and (
                t.parent not in self.techniques or t.parent != key.split(".")[0] or t.parent == key
            ):
                raise ValueError(f"Invalid subtechnique parent for {key}")
        if any(key != value.shortname for key, value in self.tactics.items()):
            raise ValueError("Invalid tactic identity")
        return self

    @classmethod
    def from_stix(
        cls,
        raw: bytes,
        *,
        domain: Domain,
        release: str | None = None,
        source_url: str | None = None,
    ) -> Self:
        bundle = json.loads(raw)
        if (
            not isinstance(bundle, dict)
            or bundle.get("type") != "bundle"
            or not isinstance(bundle.get("objects"), list)
        ):
            raise ValueError("Expected a STIX bundle")
        objects = bundle["objects"]
        if any(not isinstance(o, dict) or not isinstance(o.get("id"), str) for o in objects):
            raise ValueError("Malformed STIX object")
        if len({o["id"] for o in objects}) != len(objects):
            raise ValueError(
                "Duplicate STIX object identity/revision; select one catalogue snapshot"
            )
        collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
        if len(collections) > 1:
            expected_name = {
                "enterprise-attack": "Enterprise ATT&CK",
                "mobile-attack": "Mobile ATT&CK",
                "ics-attack": "ICS ATT&CK",
            }[domain]
            collections = [
                o
                for o in collections
                if domain in o.get("x_mitre_domains", []) or o.get("name") == expected_name
            ]
            if len(collections) != 1:
                raise ValueError("Ambiguous STIX collection version/domain")
        versions = {o.get("x_mitre_version") for o in collections}
        if len(versions) == 1:
            inferred = next(iter(versions))
            if release and inferred and release != inferred:
                raise ValueError("Declared release differs from STIX collection")
            release = release or inferred
        if not release:
            raise ValueError("Supply a release when the bundle has no unique collection version")

        def external(o, prefix):
            ids = {
                r.get("external_id")
                for r in o.get("external_references", [])
                if r.get("source_name")
                in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
                and str(r.get("external_id", "")).startswith(prefix)
            }
            if len(ids) != 1:
                raise ValueError(f"Missing or ambiguous ATT&CK identity: {o['id']}")
            return next(iter(ids))

        selected = [o for o in objects if domain in o.get("x_mitre_domains", [])]
        tactics = {}
        for o in selected:
            if o.get("type") != "x-mitre-tactic":
                continue
            key = o["x_mitre_shortname"]
            if key in tactics:
                raise ValueError("Duplicate tactic")
            tactics[key] = Tactic(
                id=external(o, "TA"),
                stix_id=o["id"],
                name=o["name"],
                shortname=key,
                revoked=o.get("revoked", False),
                deprecated=o.get("x_mitre_deprecated", False),
            )
        patterns = [o for o in selected if o.get("type") == "attack-pattern"]
        ids = {o["id"]: external(o, "T") for o in patterns}
        parents = {}
        for o in objects:
            if (
                o.get("type") == "relationship"
                and o.get("relationship_type") == "subtechnique-of"
                and o.get("revoked", False) is False
                and o.get("x_mitre_deprecated", False) is False
                and o.get("source_ref") in ids
            ):
                source, target = o["source_ref"], o.get("target_ref")
                if target not in ids:
                    raise ValueError("Missing subtechnique parent in selected domain")
                if source in parents and parents[source] != ids[target]:
                    raise ValueError("Ambiguous subtechnique parent")
                parents[source] = ids[target]
        techniques = {}
        for o in patterns:
            key = ids[o["id"]]
            if key in techniques:
                raise ValueError("Duplicate ATT&CK technique ID")
            retired = o.get("revoked", False) is True or o.get("x_mitre_deprecated", False) is True
            if o.get("x_mitre_is_subtechnique") is True and o["id"] not in parents and not retired:
                raise ValueError(f"Missing subtechnique parent: {key}")
            techniques[key] = Technique(
                id=key,
                stix_id=o["id"],
                name=o["name"],
                modified=o["modified"],
                object_version=o.get("x_mitre_version", "unknown"),
                tactics=sorted(
                    {
                        p["phase_name"]
                        for p in o.get("kill_chain_phases", [])
                        if p.get("kill_chain_name")
                        == {
                            "enterprise-attack": "mitre-attack",
                            "mobile-attack": "mitre-mobile-attack",
                            "ics-attack": "mitre-ics-attack",
                        }[domain]
                    }
                ),
                platforms=o.get("x_mitre_platforms", []),
                parent=parents.get(o["id"]),
                revoked=o.get("revoked", False),
                deprecated=o.get("x_mitre_deprecated", False),
                marking_refs=o.get("object_marking_refs", []),
            )
        return cls(
            domain=domain,
            release=release,
            source_sha256=hashlib.sha256(raw).hexdigest(),
            source_url=source_url,
            techniques=techniques,
            tactics=tactics,
            markings=[o for o in objects if o.get("type") == "marking-definition"],
        )

    def resolve(self, selection: TechniqueSelection, *, allow_retired: bool = False) -> Technique:
        if selection.technique not in self.techniques:
            raise ValueError(f"Unknown {self.domain} technique: {selection.technique}")
        t = self.techniques[selection.technique]
        ancestry = [t] + ([self.techniques[t.parent]] if t.parent else [])
        if not allow_retired and any(v.revoked or v.deprecated for v in ancestry):
            raise ValueError(f"Selected technique or parent is retired: {t.id}")
        if selection.tactic:
            if selection.tactic not in t.tactics:
                raise ValueError(f"Invalid tactic for {t.id}: {selection.tactic}")
            tactic = self.tactics[selection.tactic]
            if not allow_retired and (tactic.revoked or tactic.deprecated):
                raise ValueError("Selected tactic is retired")
        if set(selection.platforms) - set(t.platforms):
            raise ValueError(f"Unsupported platforms for {t.id}: {selection.platforms}")
        return t

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical(self.model_dump(mode="json"))).hexdigest()


def import_catalog(
    source: Path,
    destination: Path,
    *,
    domain: Domain,
    expected_sha256: str | None = None,
    release: str | None = None,
    source_url: str | None = None,
) -> Catalog:
    raw = source.read_bytes()
    if expected_sha256 and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("STIX source checksum mismatch")
    catalog = Catalog.from_stix(raw, domain=domain, release=release, source_url=source_url)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "source.stix.json").write_bytes(raw)
    write_json(destination / "catalog.json", catalog.model_dump(mode="json"))
    write_json(
        destination / "pin.json",
        {"catalog_sha256": catalog.sha256, "source_sha256": catalog.source_sha256},
    )
    return catalog


def load_catalog(path: Path | None = None) -> Catalog:
    if path is None:
        root = resources("scenar") / "resources/attack"
        catalog = Catalog.model_validate_json((root / "catalog.json").read_bytes())
        pin = json.loads((root / "pin.json").read_bytes())
    else:
        if not path.is_dir():
            raise ValueError(
                "Catalogue must be a pinned directory containing catalog.json and pin.json"
            )
        catalog = Catalog.model_validate_json((path / "catalog.json").read_bytes())
        pin = json.loads((path / "pin.json").read_bytes())
        if (path / "source.stix.json").exists() and digest(
            path / "source.stix.json"
        ) != catalog.source_sha256:
            raise ValueError("STIX source checksum mismatch")
    if pin != {"catalog_sha256": catalog.sha256, "source_sha256": catalog.source_sha256}:
        raise ValueError("Catalogue checksum mismatch")
    return catalog
