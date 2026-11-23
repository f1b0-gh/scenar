import copy
import json

import pytest

from scenar.attack import Catalog, TechniqueSelection, import_catalog, load_catalog


def stix(domain="enterprise-attack"):
    def refs(id):
        return [{"source_name": "mitre-attack", "external_id": id}]

    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "collection--test",
                "name": "Test",
                "x_mitre_version": "20.1",
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--a",
                "name": "Discovery",
                "x_mitre_shortname": "discovery",
                "x_mitre_domains": [domain],
                "external_references": refs("TA0007"),
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--parent",
                "name": "Parent",
                "modified": "2026-01-01T00:00:00Z",
                "x_mitre_version": "1.0",
                "x_mitre_domains": [domain],
                "x_mitre_platforms": ["Windows"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
                ],
                "external_references": refs("T1000"),
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--child",
                "name": "Child",
                "modified": "2026-01-01T00:00:00Z",
                "x_mitre_version": "1.0",
                "x_mitre_domains": [domain],
                "x_mitre_is_subtechnique": True,
                "x_mitre_platforms": ["Windows"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
                ],
                "external_references": refs("T1000.001"),
            },
            {
                "type": "relationship",
                "id": "relationship--p",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--child",
                "target_ref": "attack-pattern--parent",
            },
        ],
    }


def catalog(value=None):
    return Catalog.from_stix(json.dumps(value or stix()).encode(), domain="enterprise-attack")


def test_selection_resolves_revision_parent_tactic_platform():
    c = catalog()
    t = c.resolve(
        TechniqueSelection(technique="T1000.001", tactic="discovery", platforms=["Windows"])
    )
    assert t.parent == "T1000"
    assert t.object_version == "1.0"
    assert c.release == "20.1"


@pytest.mark.parametrize(
    "selection",
    [
        dict(technique="T9999"),
        dict(technique="T1000", tactic="execution"),
        dict(technique="T1000", platforms=["Linux"]),
    ],
)
def test_invalid_selection_rejected(selection):
    with pytest.raises(ValueError):
        catalog().resolve(TechniqueSelection(**selection))


@pytest.mark.parametrize("field", ["revoked", "x_mitre_deprecated"])
def test_retired_technique_requires_explicit_opt_in(field):
    value = stix()
    value["objects"][3][field] = True
    c = catalog(value)
    with pytest.raises(ValueError, match="retired"):
        c.resolve(TechniqueSelection(technique="T1000.001"))
    assert c.resolve(TechniqueSelection(technique="T1000.001"), allow_retired=True)


def test_duplicate_and_wrong_parent_fail_closed():
    value = stix()
    value["objects"].append(copy.deepcopy(value["objects"][2]))
    with pytest.raises(ValueError, match="Duplicate"):
        catalog(value)
    value = stix()
    value["objects"][-1]["target_ref"] = "missing"
    with pytest.raises(ValueError, match="parent"):
        catalog(value)


def test_import_preserves_original_bytes_and_verifies_hash(tmp_path):
    source = tmp_path / "input.json"
    raw = json.dumps(stix()).encode()
    source.write_bytes(raw)
    with pytest.raises(ValueError, match="checksum"):
        import_catalog(
            source, tmp_path / "bad", domain="enterprise-attack", expected_sha256="a" * 64
        )
    output = tmp_path / "catalog"
    c = import_catalog(source, output, domain="enterprise-attack")
    assert (output / "source.stix.json").read_bytes() == raw
    assert load_catalog(output) == c
    (output / "catalog.json").write_text("{}")
    with pytest.raises(ValueError):
        load_catalog(output)


def test_packaged_enterprise_catalogue_supports_actual_pack():
    c = load_catalog()
    assert c.release == "20.1"
    assert len(c.techniques) > 500
    for id in ("T1021.001", "T1083", "T1560.001"):
        assert c.resolve(TechniqueSelection(technique=id, platforms=["Windows"]))


def test_active_subtechnique_cannot_hide_its_parent_by_omitting_flag():
    value = stix()
    value["objects"].pop()
    value["objects"][3].pop("x_mitre_is_subtechnique")
    with pytest.raises(ValueError, match="parent"):
        catalog(value)
    projected = catalog().model_dump(mode="json")
    projected["techniques"]["T1000.001"]["parent"] = None
    with pytest.raises(ValueError, match="parent"):
        Catalog.model_validate(projected)


def test_domain_chain_duplicate_tactic_id_and_conflicting_versions_rejected():
    bad = stix()
    bad["objects"][2]["kill_chain_phases"][0]["kill_chain_name"] = "mitre-ics-attack"
    with pytest.raises(ValueError):
        catalog(bad).resolve(TechniqueSelection(technique="T1000", tactic="discovery"))
    bad = stix()
    tactic = copy.deepcopy(bad["objects"][1])
    tactic.update(id="tactic--duplicate", x_mitre_shortname="other")
    bad["objects"].append(tactic)
    with pytest.raises(ValueError):
        catalog(bad)
    bad = stix()
    bad["objects"].append(
        {
            "type": "x-mitre-collection",
            "id": "collection--other",
            "name": "Other",
            "x_mitre_version": "1",
        }
    )
    with pytest.raises(ValueError):
        Catalog.from_stix(json.dumps(bad).encode(), domain="enterprise-attack", release="9.99")


@pytest.mark.parametrize(
    "domain,chain", [("mobile-attack", "mitre-mobile-attack"), ("ics-attack", "mitre-ics-attack")]
)
def test_imported_domain_uses_its_own_kill_chain(domain, chain):
    data = stix(domain)
    for value in data["objects"]:
        if value.get("type") == "attack-pattern":
            value["kill_chain_phases"][0]["kill_chain_name"] = chain
    result = Catalog.from_stix(json.dumps(data).encode(), domain=domain)
    assert (
        result.resolve(TechniqueSelection(technique="T1000.001", tactic="discovery")).parent
        == "T1000"
    )
