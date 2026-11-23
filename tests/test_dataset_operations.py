import importlib
import sys

import pytest

from scenar.io import files
from scenar.storage import export_public
from tests.test_datasets import observed_dataset
from tests.test_generation import generation_backend


def module(name):
    return importlib.import_module("scenar.datasets." + name)


def test_smoke_covers_families_controls_and_visibility():
    specs = module("smoke").smoke_specs(300)
    assert {f for spec in specs for f in spec.families} == {
        "inventory_archive",
        "remote_access",
        "persistence",
        "credential_access",
        "c2",
    }
    assert all(set(s.variants) == {"benign", "malicious"} for s in specs)
    assert {v.mode for spec in specs for v in spec.visibility} == {
        "complete",
        "lossy",
        "delayed",
        "missing_endpoint",
    }
    assert sum(len(s.dimensions_list()) for s in specs) <= 20


def test_smoke_real_orchestration_roundtrips_qualified_fixture(tmp_path, monkeypatch):
    run, plan, _ = observed_dataset(tmp_path, monkeypatch)
    smoke = module("smoke")
    monkeypatch.setattr(smoke, "smoke_specs", lambda timeout: [plan.spec])
    backend = tmp_path / "backend"
    native = tmp_path / "native-fixture"

    def command(root, *args):
        if args[0] == "generate":
            out = args[args.index("--output") + 1]
            return [
                sys.executable,
                "-c",
                f"import shutil; shutil.copytree({str(native)!r}, {out!r})",
            ]
        return generation_backend()(root, *args)

    result = smoke.run_smoke(
        tmp_path / "smoke",
        backend=backend,
        pin=plan.backend,
        command_factory=command,
        check_readiness=False,
    )
    assert result.passed
    assert result.disk_roundtrip is True
    assert result.s3_roundtrip is None
    assert (tmp_path / "smoke/report.json").exists()


def test_smoke_failed_generation_retains_failure_and_never_reports_success(tmp_path, monkeypatch):
    from tests.test_datasets import prepare

    _, backend, plan = prepare(tmp_path)
    smoke = module("smoke")
    monkeypatch.setattr(smoke, "smoke_specs", lambda timeout: [plan.spec])
    report = smoke.run_smoke(
        tmp_path / "smoke",
        backend=backend,
        pin=plan.backend,
        command_factory=generation_backend(fail="generate"),
        check_readiness=False,
    )
    assert not report.passed
    assert report.disk_roundtrip is False
    assert report.errors
    assert (tmp_path / "smoke/matrix-0/reports/dataset.json").exists()


def test_lineage_groups_related_variants_and_keeps_metadata_private(tmp_path, monkeypatch):
    run, plan, _ = observed_dataset(tmp_path, monkeypatch)
    report = module("lineage").dataset_lineage(run)
    assert len(report.cases) == 2
    a, b = report.cases
    assert a.capture == b.capture
    assert a.environment == b.environment
    assert a.family == b.family == "inventory_archive"
    assert a.related_cases == [b.case_id]
    export_public(run, tmp_path / "public")
    assert not any("lineage" in p for p in files(tmp_path / "public"))


def test_split_assignments_are_complete_and_cannot_hide_shared_capture(tmp_path, monkeypatch):
    run, plan, _ = observed_dataset(tmp_path, monkeypatch)
    lineage = module("lineage")
    rows = [
        {"run": str(run), "case_id": c.id, "partition": "development", "exposed": False}
        for c in plan.cases
    ]
    assignments = {"schema": "scenar/dataset-splits/v1", "assignments": rows}
    assert lineage.validate_splits(assignments)["cases"] == 2
    rows[1]["partition"] = "test"
    with pytest.raises(ValueError, match="capture"):
        lineage.validate_splits(assignments)
    rows.pop()
    with pytest.raises(ValueError, match="complete"):
        lineage.validate_splits(assignments)


def test_splits_reject_unknown_cases_duplicates_and_implicit_exposure(tmp_path, monkeypatch):
    run, plan, _ = observed_dataset(tmp_path, monkeypatch)
    lineage = module("lineage")
    rows = [
        {"run": str(run), "case_id": c.id, "partition": "development", "exposed": False}
        for c in plan.cases
    ]

    def check(items):
        return lineage.validate_splits({"schema": "scenar/dataset-splits/v1", "assignments": items})

    with pytest.raises(ValueError, match="Duplicate"):
        check(rows + [rows[0]])
    with pytest.raises(ValueError, match="complete"):
        check([dict(rows[0], case_id="unknown"), rows[1]])
    del rows[0]["exposed"]
    with pytest.raises(ValueError, match="exposed"):
        check(rows)


def test_real_recipe_duration_window_supports_lineage_and_derived_cutoff(tmp_path):
    from scenar.datasets.matrix import run_dataset
    from tests.test_datasets import prepare

    run, backend, plan = prepare(tmp_path, visibility_application="derived")
    report = run_dataset(run, backend=backend, command_factory=generation_backend())
    assert all(c["error"] is None for c in report["cases"])
    assert all((run / "reports/visibility" / f"{c.id}.json").exists() for c in plan.cases)
    lineage = module("lineage").dataset_lineage(run)
    assert all(c.time_blocks == ["2024-05-27"] for c in lineage.cases)
