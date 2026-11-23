import json

import pytest

from scenar.attack import load_catalog
from scenar.backend import inspect_backend
from scenar.background import BackgroundActivity
from scenar.coverage import coverage
from scenar.runner import load_protocol, prepare_run
from scenar.scenario import AttackBinding, AttackContext
from scenar.truth import GroundTruth
from tests.test_backend import checkout


def test_preparation_freezes_attack_intent_and_background(tmp_path):
    backend = checkout(tmp_path / "backend")
    truth = GroundTruth(
        mode="intent-aware",
        episodes={"e0": {"intent": "benign", "rationale": "authorized administrative inventory"}},
    )
    run = tmp_path / "run"
    protocol = prepare_run(
        "investigation-episodes",
        run,
        backend=backend,
        pin=inspect_backend(backend),
        families=("benign_only",),
        ground_truth=truth,
        background=BackgroundActivity(profile="server"),
    )
    assert protocol.cases[0].ground_truth == truth
    assert protocol.cases[0].attack.release == "20.1"
    scenario = json.loads((run / protocol.cases[0].scenario).read_bytes())
    assert scenario["baseline_activity"]["traffic_rates"]["web"] == "high"
    assert load_protocol(run) == protocol
    path = run / "sources/attack/catalog.json"
    data = json.loads(path.read_bytes())
    data["release"] = "forged"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="checksum|catalogue"):
        load_protocol(run)


def test_detection_requires_qualified_observation_of_same_technique():
    catalog = load_catalog()
    context = AttackContext(
        domain=catalog.domain,
        release=catalog.release,
        catalog_sha256=catalog.sha256,
        source_sha256=catalog.source_sha256,
        mappings=[AttackBinding(record_id="a#0", technique="T1083")],
    )
    with pytest.raises(ValueError, match="unqualified"):
        coverage(context, catalog, detected={("T1083", "native#1")})
    report = coverage(
        context, catalog, observations={"a#0": ["native#1"]}, detected={("T1083", "native#1")}
    )
    assert report["techniques"][0]["observed"] == 1
    assert report["techniques"][0]["detected"] == 1
    assert report["techniques"][0]["detected_observation_ids"] == ["native#1"]


def test_annotated_replay_uses_same_native_bytes_without_inferred_intent(tmp_path):
    import os
    from pathlib import Path

    from scenar.analysis_reports import bundle_coverage
    from scenar.replay import replay_run, verify_bundle

    source = os.environ.get("SCENAR_PARITY_ARCHIVE")
    if not source:
        pytest.skip("Requires retained native archive")
    destination = tmp_path / "replayed"
    result = replay_run(
        Path(source),
        destination,
        annotate_attack=True,
        ground_truth=GroundTruth(mode="intent-aware"),
    )
    assert verify_bundle(destination) == result
    assert result.provenance == "transformed"
    report = bundle_coverage(destination, tmp_path / "coverage")
    assert any(row["observed"] > 0 for row in report["techniques"])
    assert all(row["detected"] == 0 for row in report["techniques"])
    for path in (destination / "private/attempts").glob("*/intent-ground-truth.json"):
        truth = GroundTruth.model_validate_json(path.read_bytes())
        assert truth.mode == "intent-aware"
        assert all(label.intent == "unknown" for label in truth.labels.values())
    for path in (destination / "public").glob("*.json"):
        content = path.read_text()
        assert '"intent"' not in content and '"is_malicious"' not in content


def test_coverage_rejects_fabricated_native_record_after_rehashing_index(tmp_path):
    import os
    import shutil
    from pathlib import Path

    from scenar.analysis_reports import bundle_coverage
    from scenar.coverage import Detections
    from scenar.io import digest, write_json

    source = os.environ.get("SCENAR_ANNOTATED_ARCHIVE")
    if not source:
        pytest.skip("Requires annotated frozen test replay")
    root = tmp_path / "bundle"
    # Copies metadata only; preserve original immutable native/source bytes.
    shutil.copytree(Path(source), root, copy_function=shutil.copyfile)
    load_protocol(root)
    manifest = json.loads((root / "manifest.json").read_bytes())
    capture = next(c for c in manifest["captures"] if c["qualified"])
    folder = root / "private/attempts" / capture["id"]
    path = folder / "private-observation-index.json"
    index = json.loads(path.read_bytes())
    row = next(r for r in index["observations"] if r["authored_record_id"].startswith("discover-"))
    row["native_record_id"] = "MISSING-RECORD"
    row["observation_id"] = row["native_file"] + "#MISSING-RECORD"
    write_json(path, index)
    entry = next(f for f in manifest["files"] if f["path"] == path.relative_to(root).as_posix())
    entry.update(sha256=digest(path), size=path.stat().st_size)
    write_json(root / "manifest.json", manifest)
    detection = Detections(
        detector="test",
        detections=[
            {
                "case_id": capture["id"],
                "technique": "T1083",
                "observation_id": row["observation_id"],
            }
        ],
    )
    with pytest.raises(ValueError, match="reconcil|observation"):
        bundle_coverage(root, tmp_path / "coverage", detections=detection)
