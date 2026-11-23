import importlib
import json
from pathlib import Path

import pytest

from scenar.generation import generate_scenario
from scenar.io import files
from tests.test_generation import generation_backend, setup_generation


def api():
    return importlib.import_module("scenar.datasets.diagnostics")


def test_generation_records_measured_stages_and_native_volume(tmp_path):
    source, out, options = setup_generation(tmp_path)
    generate_scenario(source, out, **options, command_factory=generation_backend())
    metrics = json.loads((out / "reports/measurements.json").read_bytes())
    assert metrics["status"] == "succeeded"
    assert {s["stage"] for s in metrics["stages"]} == {"validate", "generate", "quality"}
    assert all(s["elapsed_seconds"] >= 0 for s in metrics["stages"])
    assert metrics["native_files"] == 2
    assert metrics["native_bytes"] == sum(
        p.stat().st_size for p in (out / "private/native").rglob("*") if p.is_file()
    )


def test_history_excludes_failed_and_different_workloads(tmp_path):
    source, out, options = setup_generation(tmp_path)
    generate_scenario(source, out, **options, command_factory=generation_backend())
    failed = tmp_path / "failed"
    with pytest.raises(RuntimeError):
        generate_scenario(
            source, failed, **options, command_factory=generation_backend(fail="generate")
        )
    other = tmp_path / "other"
    source.write_text('{"name":"different","storyline":[]}')
    generate_scenario(source, other, **options, command_factory=generation_backend())
    result = api().timing_report(out, [out, failed, other])
    assert result["comparable_successes"] == 1
    assert result["failed_samples"] == 1
    assert result["incomparable_samples"] == 1
    assert result["stages"]["generate"]["samples"] == 1
    assert result["stages"]["generate"]["min_seconds"] >= 0
    assert result["native_bytes"]["max"] > 0


def test_history_rejects_tampered_bundle_and_deduplicates_same_capture_path(tmp_path):
    source, out, options = setup_generation(tmp_path)
    generate_scenario(source, out, **options, command_factory=generation_backend())
    assert api().timing_report(out, [out, out])["comparable_successes"] == 1
    (out / "private/native/used-seed.txt").write_text("tampered")
    with pytest.raises(ValueError, match="checksum"):
        api().timing_report(out, [out])


def test_preflight_reports_identity_failure_and_does_not_write_output(tmp_path):
    source, out, options = setup_generation(tmp_path)
    backend = options["backend"]
    (backend / "uv.lock").write_text("changed")
    before = files(tmp_path)
    result = api().preflight(backend, options["pin"], out)
    assert not result.ready
    assert any(c.name == "backend_identity" and c.status == "failed" for c in result.checks)
    assert files(tmp_path) == before
    assert not out.exists()


def test_spool_ancestry_reports_untrusted_owner_and_unsafe_write_modes(tmp_path):
    import os
    from types import SimpleNamespace

    def metadata(path):
        return SimpleNamespace(st_uid=999999, st_mode=0o40755)

    checks = api().check_spool_ancestry(tmp_path, uid=os.geteuid(), stat_path=metadata)
    assert checks.status == "failed" and "owned" in checks.detail

    def writable(path):
        return SimpleNamespace(st_uid=0, st_mode=0o40777)

    checks = api().check_spool_ancestry(tmp_path, uid=os.geteuid(), stat_path=writable)
    assert checks.status == "failed" and "sticky" in checks.detail


def test_spool_ancestry_allows_sticky_root_and_private_owned_path(tmp_path):
    import os
    from types import SimpleNamespace

    def metadata(path):
        return SimpleNamespace(
            st_uid=os.geteuid(), st_mode=0o41777 if path == Path("/") else 0o40700
        )

    assert (
        api().check_spool_ancestry(tmp_path, uid=os.geteuid(), stat_path=metadata).status
        == "passed"
    )
