"""Restricted per-capture truth and evidence-backed ATT&CK reporting."""

import json
from pathlib import Path

import yaml

from .attack import load_catalog
from .bundle import Case, Qualification
from .coverage import Detections, coverage, navigator
from .io import digest, safe_path, write_json
from .scenario import authored_cardinality
from .storage import verify_capture_qualification
from .truth import GroundTruth, IntentPredictions, annotate_native_truth, grade_intent


def qualified_index(folder: Path, case: Case) -> list[dict]:
    from .evaluation.audit import read_records
    from .evaluation.models import Record
    from .evaluation.native import reconcile_case

    stored = json.loads((folder / "private-observation-index.json").read_bytes())["observations"]
    records, hashes = read_records(folder / "bundle")
    raw = json.loads((folder / "bundle/GROUND_TRUTH.json").read_bytes())
    _, expected = reconcile_case(
        raw, [Record.model_validate(r) for r in records], case.model_dump(mode="json"), hashes
    )
    if stored != expected:
        raise ValueError("Native observation index differs from source reconciliation")
    return expected


def capture_reports(run: Path, case: Case, qualification: Qualification) -> None:
    folder = safe_path(run, f"private/attempts/{case.id}")
    index = qualified_index(folder, case) if qualification.native_passed else []
    members = {m.authored_record_id: m.episode_ids for m in case.private.members}
    truth = case.ground_truth.bind(
        members, {r["authored_record_id"]: r["observation_id"] for r in index}
    )
    write_json(folder / "intent-ground-truth.json", truth.model_dump(mode="json"))
    raw_path = folder / "bundle/GROUND_TRUTH.json"
    if raw_path.exists():
        overlay = annotate_native_truth(
            json.loads(raw_path.read_bytes()),
            case.ground_truth,
            members=members,
            authored_counts=authored_cardinality(
                yaml.safe_load(safe_path(run, case.scenario).read_text())
            ),
        )
        overlay["source_sha256"] = digest(raw_path)
        overlay["eligible"] = qualification.eligible
        write_json(folder / "scenar-ground-truth.json", overlay)
    write_json(
        folder / "intent-assessment.json",
        {
            "mode": truth.mode,
            "is_malicious": {id: label.is_malicious for id, label in truth.labels.items()},
            "unobserved_authored_labels": sorted(
                set(case.ground_truth.labels) - {r["authored_record_id"] for r in index}
            ),
            "reference_policy_intent_metrics": grade_intent(truth, IntentPredictions(decisions={})),
            "note": "Reference policies request investigation; they do not predict maliciousness. Empty predictions remain abstentions.",
        },
    )
    if case.attack:
        catalog = load_catalog(run / "sources/attack")
        observations = (
            {r["authored_record_id"]: [r["observation_id"]] for r in index}
            if qualification.eligible
            else {}
        )
        report = coverage(case.attack, catalog, observations=observations)
        report["eligible"] = qualification.eligible
        write_json(folder / "attack-coverage.json", report)


def bundle_coverage(run: Path, output: Path, *, detections: Detections | None = None) -> dict:
    from .replay import verify_bundle
    from .runner import load_protocol

    manifest = verify_bundle(run)
    protocol = load_protocol(run)
    if not protocol.catalog_sha256:
        raise ValueError(
            "This historical run has no frozen ATT&CK mapping; no coverage is inferred"
        )
    catalog = load_catalog(run / "sources/attack")
    if {c.id for c in manifest.captures} != {c.id for c in protocol.cases}:
        raise ValueError("Capture population differs from frozen protocol")
    if output.exists():
        raise FileExistsError(output)
    declared = detections.detections if detections else []
    if any(d.case_id not in {c.id for c in protocol.cases} for d in declared):
        raise ValueError("Detection references unknown capture")
    reports = []
    for case in protocol.cases:
        folder = safe_path(run, f"private/attempts/{case.id}")
        qpath = folder / "qualification.json"
        eligible = False
        if qpath.exists():
            q = Qualification.model_validate_json(qpath.read_bytes())
            eligible = q.eligible and next(
                c.qualified for c in manifest.captures if c.id == case.id
            )
        if eligible:
            verify_capture_qualification(run, next(c for c in manifest.captures if c.id == case.id))
        index = qualified_index(folder, case) if eligible else []
        report = coverage(
            case.attack,
            catalog,
            observations={r["authored_record_id"]: [r["observation_id"]] for r in index},
            detected={(d.technique, d.observation_id) for d in declared if d.case_id == case.id},
        )
        reports.append({"case_id": case.id, "eligible": eligible, "report": report})
    rows = {}
    for case in reports:
        for row in case["report"]["techniques"]:
            aggregate = rows.setdefault(
                row["technique"],
                {
                    "technique": row["technique"],
                    "name": row["name"],
                    "authored": 0,
                    "observed": 0,
                    "detected": 0,
                },
            )
            for key in ("authored", "observed", "detected"):
                aggregate[key] += row[key]
    report = {
        "schema": "scenar/attack-coverage/v1",
        "domain": catalog.domain,
        "release": catalog.release,
        "catalog_sha256": catalog.sha256,
        "source_sha256": catalog.source_sha256,
        "techniques": list(rows.values()),
        "cases": reports,
        "detector": detections.detector if detections else None,
        "scope": "Counts across attempted captures; views/sweeps do not multiply evidence. Detector reports are not operational certification.",
        "source_manifest_sha256": digest(run / "manifest.json"),
    }
    output.mkdir(parents=True)
    write_json(output / "coverage.json", report)
    for stage in ("authored", "observed", "detected"):
        write_json(output / f"navigator-{stage}.json", navigator(report, stage))
    return report


def grade_bundle_intent(run: Path, predictions: dict[str, IntentPredictions], output: Path) -> dict:
    from .replay import verify_bundle
    from .runner import load_protocol

    manifest = verify_bundle(run)
    protocol = load_protocol(run)
    if set(predictions) - {c.id for c in protocol.cases}:
        raise ValueError("Intent predictions reference unknown capture")
    reports = []
    for case in protocol.cases:
        folder = safe_path(run, f"private/attempts/{case.id}")
        path = folder / "intent-ground-truth.json"
        if not path.exists():
            reports.append(
                {
                    "case_id": case.id,
                    "status": "unqualified-or-unobserved",
                    "mode": case.ground_truth.mode,
                }
            )
            continue
        truth = GroundTruth.model_validate_json(path.read_bytes())
        reports.append(
            {
                "case_id": case.id,
                "diagnostic_only": not next(
                    c.qualified for c in manifest.captures if c.id == case.id
                ),
                "metrics": grade_intent(
                    truth, predictions.get(case.id, IntentPredictions(decisions={}))
                ),
            }
        )
    if output.exists():
        raise FileExistsError(output)
    report = {
        "schema": "scenar/intent-report/v1",
        "source_manifest_sha256": digest(run / "manifest.json"),
        "cases": reports,
    }
    write_json(output, report)
    return report
