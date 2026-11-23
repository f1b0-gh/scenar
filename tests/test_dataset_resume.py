import importlib
import json

import pytest

from scenar.datasets import matrix
from scenar.io import files
from scenar.replay import verify_bundle
from tests.test_datasets import prepare
from tests.test_generation import generation_backend


def resume(*args, **kwargs):
    return importlib.import_module("scenar.datasets.resume").resume_dataset(*args, **kwargs)


def test_interruption_reuses_verified_generation_and_finishes_remaining_case(tmp_path, monkeypatch):
    run, backend, plan = prepare(tmp_path)
    original = matrix.generate_scenario
    calls = 0

    def interrupt(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt()
        return original(*args, **kwargs)

    monkeypatch.setattr(matrix, "generate_scenario", interrupt)
    with pytest.raises(KeyboardInterrupt):
        matrix.run_dataset(run, backend=backend, command_factory=generation_backend())
    before = files(run)
    monkeypatch.setattr(matrix, "generate_scenario", original)
    events = []
    report = resume(
        run,
        tmp_path / "resumed",
        backend=backend,
        command_factory=generation_backend(),
        progress=events.append,
    )
    assert report["generated"] == 2
    assert report["reused"] == 1
    assert files(run) == before
    assert verify_bundle(tmp_path / "resumed").parent_sha256
    assert any(e.state == "reused" for e in events)
    assert events[-1].completed == 2


def test_retry_retains_failed_attempts_and_original_bundle(tmp_path):
    run, backend, plan = prepare(tmp_path)
    matrix.run_dataset(run, backend=backend, command_factory=generation_backend(fail="generate"))
    before = files(run)
    target = tmp_path / "retry"
    report = resume(run, target, backend=backend, command_factory=generation_backend())
    assert report["generated"] == 2 and report["reused"] == 0
    assert files(run) == before
    history = target / "private/history/previous"
    assert files(history) == before
    previous = json.loads((history / "reports/dataset.json").read_bytes())
    assert previous["generated"] == 0
    verify_bundle(target)
    with pytest.raises(FileExistsError):
        resume(run, target, backend=backend)


def test_tampered_completed_capture_is_rejected_before_copy(tmp_path):
    run, backend, plan = prepare(tmp_path)
    matrix.run_dataset(run, backend=backend, command_factory=generation_backend())
    path = run / "private/attempts" / plan.cases[0].id / "private/native/used-seed.txt"
    path.write_text("tampered")
    with pytest.raises(ValueError, match="checksum"):
        resume(run, tmp_path / "retry", backend=backend, command_factory=generation_backend())
    assert not (tmp_path / "retry").exists()


def test_resume_rejects_resealed_wrong_seed_before_reusing(tmp_path):
    from tests.test_datasets import reseal

    run, backend, plan = prepare(tmp_path)
    matrix.run_dataset(run, backend=backend, command_factory=generation_backend())
    folder = run / "private/attempts" / plan.cases[0].id
    path = folder / "sources/generation.json"
    data = json.loads(path.read_bytes())
    data["seed"] = 99
    path.write_text(json.dumps(data))
    reseal(folder)
    reseal(run)
    with pytest.raises(ValueError, match="provenance"):
        resume(run, tmp_path / "retry", backend=backend, command_factory=generation_backend())
    assert not (tmp_path / "retry").exists()


def test_interruption_before_capture_seal_retries_and_keeps_unsealed_attempt(tmp_path, monkeypatch):
    import scenar.generation as generation

    run, backend, plan = prepare(tmp_path)
    original = generation._seal_generation

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(generation, "_seal_generation", interrupt)
    with pytest.raises(KeyboardInterrupt):
        matrix.run_dataset(run, backend=backend, command_factory=generation_backend())
    monkeypatch.setattr(generation, "_seal_generation", original)
    report = resume(run, tmp_path / "retry", backend=backend, command_factory=generation_backend())
    assert report["generated"] == 2 and report["reused"] == 0
    assert (
        tmp_path / "retry/private/history/previous/private/attempts" / plan.cases[0].id
    ).exists()
