"""Python-first inputs with an optional Nickel frontend."""

import json
import shutil
import subprocess
from datetime import date, datetime
from pathlib import Path

import yaml

from .attack import load_catalog
from .background import BackgroundActivity
from .coverage import coverage, navigator
from .io import digest, write_json
from .scenario import ScenarioDocument, compile_document, nickel_attack_settings
from .truth import GroundTruth


def build(
    source: Path,
    output: Path,
    overrides: list[str] | None = None,
    *,
    catalog_path: Path | None = None,
    background: BackgroundActivity | None = None,
    ground_truth: GroundTruth | None = None,
    noise_only: bool = False,
) -> Path:
    source = source / "main.ncl" if source.is_dir() else source
    overrides = overrides or []
    if source.suffix == ".ncl":
        if not shutil.which("nickel"):
            raise ValueError("Nickel is an optional frontend; install nickel or supply YAML/JSON")
        command = ["nickel", "export", "-f", "json", str(source.resolve()), "--field", "out"]
        if overrides:
            command += ["--", *overrides]
        process = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if process.returncode:
            raise ValueError(process.stderr.strip())
        compiled = json.loads(process.stdout)
        scenario = {
            "schema": "scenar/scenario/v1",
            "evidenceforge": compiled["evidenceforge"],
            **nickel_attack_settings(compiled),
        }
    else:
        if overrides:
            raise ValueError("Field overrides are supported only by the Nickel frontend")
        scenario = yaml.safe_load(source.read_text())

        def convert(value):
            if isinstance(value, (date, datetime)):
                return value.isoformat()
            raise TypeError(f"Unsupported input value: {type(value).__name__}")

        scenario = json.loads(json.dumps(scenario, default=convert, allow_nan=False))
        compiled = {}
    if not isinstance(scenario, dict):
        raise ValueError("Scenario must be a mapping")
    document = ScenarioDocument.model_validate(
        scenario if scenario.get("schema") == "scenar/scenario/v1" else {"evidenceforge": scenario}
    )
    if background is not None:
        document.background = background
    if ground_truth is not None:
        document.ground_truth = ground_truth
    catalog = load_catalog(catalog_path)
    scenario, attack = compile_document(document, catalog, noise_only=noise_only)
    effective_truth = (
        GroundTruth(mode=document.ground_truth.mode) if noise_only else document.ground_truth
    )
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "private/scenario.json", scenario)
    write_json(output / "private/attack.json", attack.model_dump(mode="json"))
    write_json(output / "private/ground-truth.json", effective_truth.model_dump(mode="json"))
    write_json(
        output / "private/background.json",
        {
            "config": document.background.model_dump(mode="json") if document.background else None,
            "noise_only": noise_only,
            "intended_intent": "benign" if document.background else "unknown",
            "scope": "Population-level author intent; unindexed individual observations remain unknown",
        },
    )
    write_json(output / "sources/attack/catalog.json", catalog.model_dump(mode="json"))
    write_json(
        output / "sources/attack/pin.json",
        {"catalog_sha256": catalog.sha256, "source_sha256": catalog.source_sha256},
    )
    report = coverage(attack, catalog)
    write_json(output / "reports/attack-authored.json", report)
    write_json(output / "private/navigator-layer.json", navigator(report))
    for key, filename in (
        ("graph", "attack-graph.json"),
        ("storage", "storage.json"),
    ):
        if key in compiled:
            write_json(output / "private" / filename, compiled[key])
    write_json(
        output / "sources/input.json",
        {"filename": source.name, "sha256": digest(source), "overrides": overrides},
    )
    shutil.copyfile(source, output / "sources" / source.name)
    return output / "private/scenario.json"
