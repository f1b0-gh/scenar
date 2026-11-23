import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from scenar.backend import inspect_backend
from scenar.datasets.matrix import DatasetSpec, load_dataset, prepare_dataset, run_dataset
from scenar.io import digest
from scenar.replay import verify_bundle
from scenar.storage import export_public, publish_bundle, pull_bundle
from tests.test_backend import checkout
from tests.test_generation import generation_backend


def prepare(tmp_path, **overrides):
    backend = checkout(tmp_path / "backend")
    spec = DatasetSpec(
        families=["inventory_archive"],
        variants=["benign", "malicious"],
        sizes=["small"],
        seeds=[17],
        start=datetime(2024, 5, 27, 12, tzinfo=timezone.utc),
        **overrides,
    )
    run = tmp_path / "run"
    plan = prepare_dataset(spec, run, backend=backend, pin=inspect_backend(backend))
    return run, backend, plan


def test_frozen_matrix_is_deterministic_and_preserves_intent_variants(tmp_path):
    run, backend, plan = prepare(tmp_path)
    assert len(plan.cases) == 2
    other = prepare_dataset(plan.spec, tmp_path / "other", backend=backend, pin=plan.backend)
    assert [c.id for c in plan.cases] == [c.id for c in other.cases]
    assert load_dataset(run) == plan
    intents = []
    for case in plan.cases:
        data = json.loads((run / case.scenario).read_bytes())
        intents.append({v["intent"] for v in data["ground_truth"]["labels"].values()})
        assert data["evidenceforge"]["name"] == "synthetic-workflow"
    assert "malicious" not in intents[0] and "malicious" in intents[1]
    source = run / plan.cases[0].scenario
    source.write_text(source.read_text() + " ")
    with pytest.raises(ValueError, match="changed"):
        load_dataset(run)


@pytest.mark.parametrize(
    "change",
    [
        {"seeds": [1, 1]},
        {"sizes": []},
        {"seeds": [-1]},
        {"seeds": [True]},
        {"variants": ["malicious", "malicious"]},
        {"families": ["unsupported"]},
        {"stage_timeout_seconds": 0},
        {"start": "2024-05-27T12:00:00"},
    ],
)
def test_dataset_spec_rejects_ambiguous_or_invalid_matrix(change):
    with pytest.raises(ValueError):
        DatasetSpec(**change)


def test_failure_keeps_every_slot_and_allows_only_diagnostic_publication(tmp_path):
    run, backend, plan = prepare(tmp_path)
    report = run_dataset(run, backend=backend, command_factory=generation_backend(fail="generate"))
    assert report["planned"] == report["attempted"] == 2
    assert report["qualified"] == 0 and not report["execution_complete"]
    assert len(report["cases"]) == 2
    assert all(c["error"] for c in report["cases"])
    assert not verify_bundle(run).qualified
    with pytest.raises(ValueError, match="qualified"):
        publish_bundle(run, str(tmp_path / "store"))
    uri = publish_bundle(run, str(tmp_path / "store"), diagnostic=True)
    assert not pull_bundle(uri, tmp_path / "pulled").qualified
    assert not (tmp_path / "store/latest.json").exists()
    with pytest.raises(ValueError, match="started"):
        run_dataset(run, backend=backend, command_factory=generation_backend())


def test_backend_acceptance_does_not_replace_native_effect_audit(tmp_path):
    run, backend, plan = prepare(tmp_path)
    report = run_dataset(run, backend=backend, command_factory=generation_backend())
    assert report["execution_complete"]
    assert report["qualified"] == 0
    assert all(not c["native_passed"] for c in report["cases"])
    exported = tmp_path / "public"
    export_public(run, exported)
    assert not list(exported.rglob("*GROUND_TRUTH*"))
    assert not list(exported.rglob("*scenario*"))
    assert not list(exported.rglob("*seed*"))


def test_plan_population_cannot_be_truncated_without_changing_freeze(tmp_path):
    run, backend, plan = prepare(tmp_path)
    path = run / "dataset.json"
    content = json.loads(path.read_bytes())
    content["cases"] = content["cases"][:1]
    path.write_text(json.dumps(content))
    with pytest.raises(ValueError, match="changed"):
        load_dataset(run)


def test_preparation_rejects_existing_directory_without_mutation(tmp_path):
    run, backend, plan = prepare(tmp_path)
    before = digest(run / "dataset.json")
    with pytest.raises(FileExistsError):
        prepare_dataset(plan.spec, run, backend=backend, pin=plan.backend)
    assert digest(run / "dataset.json") == before


def observed_dataset(tmp_path, monkeypatch):
    from scenar.datasets import matrix
    from scenar.scenario import ScenarioDocument
    from tests.test_dataset_audit import END, START, expectation, process, write_native

    native = write_native(tmp_path / "native-fixture")
    row = process()
    scenario = {
        "name": "synthetic-workflow",
        "time_window": {"start": START, "end": END},
        "environment": {"systems": [{"hostname": "FILE-01", "os": "Windows Server 2022"}]},
        "output": {
            "logs": [{"format": "windows_event_sysmon"}, {"format": "windows_event_security"}]
        },
        "storyline": [
            {
                "id": "archive",
                "time": "+60s",
                "actor": "operator01",
                "system": "FILE-01",
                "events": [
                    {
                        "type": "process",
                        "process_name": row["data"]["Image"],
                        "command_line": row["data"]["CommandLine"],
                    }
                ],
            }
        ],
    }
    monkeypatch.setattr(
        matrix,
        "build_recipe",
        lambda *args, **kwargs: SimpleNamespace(
            document=ScenarioDocument(evidenceforge=scenario),
            expectations=[expectation(authored_event_id="archive#0")],
            metadata={},
        ),
    )
    run, backend, plan = prepare(tmp_path)

    def command(root, *args):
        if args[0] == "generate":
            out = args[args.index("--output") + 1]
            return [
                sys.executable,
                "-c",
                f"import shutil; shutil.copytree({str(native)!r},{out!r})",
            ]
        return generation_backend()(root, *args)

    report = run_dataset(run, backend=backend, command_factory=command)
    return run, plan, report


def test_observed_dataset_promotes_and_exports_only_native_data(tmp_path, monkeypatch):
    run, plan, report = observed_dataset(tmp_path, monkeypatch)
    assert report["qualified"] == 2
    assert report["distinct_native_captures"] == 1
    uri = publish_bundle(run, str(tmp_path / "store"))
    assert pull_bundle(uri, tmp_path / "pulled").qualified
    export_public(run, tmp_path / "export")
    exported = [p for p in (tmp_path / "export").rglob("*") if p.is_file()]
    assert exported and all(p.suffix == ".xml" for p in exported)
    assert not any("private" in p.parts for p in exported)


def test_rehashed_audit_cannot_invent_native_coverage(tmp_path, monkeypatch):
    from scenar.bundle import Artifact
    from scenar.io import files, write_json

    run, plan, report = observed_dataset(tmp_path, monkeypatch)
    assert report["qualified"] == 2
    path = run / "reports/audits" / f"{plan.cases[0].id}.json"
    audit = json.loads(path.read_bytes())
    audit["effects"][0]["evidence_ids"] = ["fabricated-record"]
    write_json(path, audit)
    from scenar.bundle import BundleManifest

    manifest = BundleManifest.model_validate_json((run / "manifest.json").read_bytes())
    manifest.files = [
        Artifact(path=n, sha256=s, size=(run / n).stat().st_size)
        for n, s in files(run).items()
        if n != "manifest.json"
    ]
    write_json(run / "manifest.json", manifest.model_dump(mode="json", by_alias=True))
    with pytest.raises(ValueError, match="audit"):
        publish_bundle(run, str(tmp_path / "store"))


def test_generation_rejects_implementation_drift_after_preparation(tmp_path, monkeypatch):
    import shutil

    from scenar.datasets import matrix

    run, backend, plan = prepare(tmp_path)
    changed = tmp_path / "implementation"
    shutil.copytree(run / "sources/scenar", changed)
    with (changed / "generation.py").open("a") as stream:
        stream.write("\n# changed generation semantics\n")
    monkeypatch.setattr(matrix, "PACKAGE", changed, raising=False)
    with pytest.raises(ValueError, match="implementation"):
        run_dataset(run, backend=backend, command_factory=generation_backend())
    assert not (run / "reports/dataset-started.json").exists()


def test_invalid_generation_status_retains_later_matrix_slots(tmp_path, monkeypatch):
    from scenar.datasets import matrix

    run, backend, plan = prepare(tmp_path)
    original = matrix.generate_scenario

    def corrupt(*args, **kwargs):
        output = original(*args, **kwargs)
        (output / "reports/generation.json").write_text("invalid json")
        return output

    monkeypatch.setattr(matrix, "generate_scenario", corrupt)
    report = run_dataset(run, backend=backend, command_factory=generation_backend())
    assert report["attempted"] == report["planned"] == 2
    assert report["qualified"] == 0 and not report["execution_complete"]
    assert all(c["error"] for c in report["cases"])
    assert not verify_bundle(run).qualified


def reseal(root):
    from scenar.bundle import Artifact, BundleManifest
    from scenar.io import files, write_json

    manifest = BundleManifest.model_validate_json((root / "manifest.json").read_bytes())
    manifest.files = [
        Artifact(path=n, sha256=s, size=(root / n).stat().st_size)
        for n, s in files(root).items()
        if n != "manifest.json"
    ]
    write_json(root / "manifest.json", manifest.model_dump(mode="json", by_alias=True))


@pytest.mark.parametrize("field,value", [("seed", 99), ("stage_timeout_seconds", 1)])
def test_qualified_publication_rejects_changed_execution_provenance(
    tmp_path, monkeypatch, field, value
):
    run, plan, report = observed_dataset(tmp_path, monkeypatch)
    assert report["qualified"] == 2
    folder = run / "private/attempts" / plan.cases[0].id
    path = folder / "sources/generation.json"
    options = json.loads(path.read_bytes())
    options[field] = value
    path.write_text(json.dumps(options))
    reseal(folder)
    reseal(run)
    with pytest.raises(ValueError, match="provenance"):
        publish_bundle(run, str(tmp_path / "store"))


def test_public_export_rejects_extra_private_data_even_with_valid_hashes(tmp_path, monkeypatch):
    run, plan, report = observed_dataset(tmp_path, monkeypatch)
    assert report["qualified"] == 2
    (run / "public/labels.json").write_text('{"intent":"malicious"}')
    reseal(run)
    with pytest.raises(ValueError, match="allowlisted"):
        export_public(run, tmp_path / "leaked")
    assert not (tmp_path / "leaked").exists()


@pytest.mark.parametrize("artifact", ["ground-truth.json", "scenar-ground-truth.json"])
def test_qualified_publication_rejects_changed_private_truth(tmp_path, monkeypatch, artifact):
    run, plan, report = observed_dataset(tmp_path, monkeypatch)
    assert report["qualified"] == 2
    folder = run / "private/attempts" / plan.cases[0].id
    path = folder / "private" / artifact
    truth = json.loads(path.read_bytes())
    if artifact == "ground-truth.json":
        truth["mode"] = "intent-aware"
    else:
        truth["events"][0]["is_malicious"] = True
    path.write_text(json.dumps(truth))
    reseal(folder)
    reseal(run)
    with pytest.raises(ValueError, match="truth"):
        publish_bundle(run, str(tmp_path / "store"))
