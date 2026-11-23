import json

import pytest

from scenar.authoring import build
from scenar.io import write_json


def document():
    return {
        "schema": "scenar/scenario/v1",
        "evidenceforge": {
            "name": "mixed",
            "storyline": [
                {"id": "normal", "events": [{"type": "process", "technique": "T1083"}]},
                {"id": "adversary", "events": [{"type": "process", "technique": "T1083"}]},
            ],
        },
        "attack": {
            "domain": "enterprise-attack",
            "release": "20.1",
            "mappings": [
                {
                    "record_id": "normal#0",
                    "technique": "T1083",
                    "tactic": "discovery",
                    "platforms": ["Windows"],
                }
            ],
        },
        "ground_truth": {
            "mode": "intent-aware",
            "labels": {
                "normal#0": {"intent": "benign", "rationale": "routine inventory"},
                "adversary#0": {"intent": "malicious", "rationale": "adversary inventory"},
            },
        },
        "background": {"profile": "office"},
    }


def test_shared_authoring_compiles_tags_noise_and_private_intent(tmp_path):
    source = tmp_path / "scenario.json"
    write_json(source, document())
    out = tmp_path / "built"
    backend = build(source, out)
    value = json.loads(backend.read_bytes())
    assert "ground_truth" not in value and "attack" not in value
    assert value["baseline_activity"]["traffic_rates"]["user_activity"] == "medium"
    private = json.loads((out / "private/ground-truth.json").read_bytes())
    assert private["mode"] == "intent-aware"
    assert private["labels"]["normal#0"]["intent"] == "benign"
    report = json.loads((out / "reports/attack-authored.json").read_bytes())
    assert report["techniques"][0]["authored"] == 2
    assert report["techniques"][0]["observed"] == 0
    layer = json.loads((out / "private/navigator-layer.json").read_bytes())
    assert layer["versions"]["attack"] == "20.1" and layer["techniques"][0]["score"] == 2
    assert not (out / "public").exists()


def test_unknown_technique_domain_or_intent_reference_rejected_before_output(tmp_path):
    for index, change in enumerate(("technique", "domain", "intent")):
        doc = document()
        if change == "technique":
            doc["evidenceforge"]["storyline"][0]["events"][0]["technique"] = "T9999"
        if change == "domain":
            doc["attack"]["domain"] = "mobile-attack"
        if change == "intent":
            doc["ground_truth"]["labels"]["absent#0"] = {"intent": "benign", "rationale": "invalid"}
        source = tmp_path / f"source-{index}.json"
        write_json(source, doc)
        with pytest.raises(ValueError):
            build(source, tmp_path / f"out-{index}")
        assert not (tmp_path / f"out-{index}").exists()


def test_noise_only_from_mixed_document_drops_focal_mapping_and_labels(tmp_path):
    source = tmp_path / "source.json"
    write_json(source, document())
    out = tmp_path / "ambient"
    backend = build(source, out, noise_only=True)
    assert json.loads(backend.read_bytes())["storyline"] == []
    assert json.loads((out / "private/attack.json").read_bytes())["mappings"] == []
    assert json.loads((out / "private/ground-truth.json").read_bytes())["labels"] == {}
    assert json.loads((out / "sources/input.json").read_bytes())["filename"] == "source.json"


def test_backend_null_storyline_is_valid_for_ambient_only_input(tmp_path):
    source = tmp_path / "ambient.json"
    write_json(source, {"name": "ambient", "storyline": None})
    assert build(source, tmp_path / "built").exists()
