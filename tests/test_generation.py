import json
import sys

import pytest

from scenar.backend import inspect_backend
from scenar.background import BackgroundActivity
from scenar.generation import generate_scenario
from scenar.replay import verify_bundle
from scenar.storage import publish_bundle, pull_bundle
from tests.test_backend import checkout


def test_library_noise_generation_dispatches_backend_and_keeps_truth_private(tmp_path):
    backend = checkout(tmp_path / "backend")
    source = tmp_path / "source.yaml"
    source.write_text("name: ambient\nstoryline: []\n")
    calls = []

    def command(root, *args):
        calls.append(args)
        if args[0] == "generate":
            destination = args[args.index("--output") + 1]
            code = f"from pathlib import Path; p=Path({destination!r}); p.mkdir(parents=True); (p/'GROUND_TRUTH.json').write_text('{{\"events\":[]}}')"
        elif args[0] == "eval":
            code = "print('{\"acceptance_passed\": true}')"
        else:
            code = "raise SystemExit(0)"
        return [sys.executable, "-c", code]

    out = tmp_path / "out"
    result = generate_scenario(
        source,
        out,
        backend=backend,
        pin=inspect_backend(backend),
        background=BackgroundActivity(profile="office"),
        noise_only=True,
        seed=31,
        command_factory=command,
    )
    assert result == out
    assert calls[1][-2:] == ("--seed", "31")
    scenario = json.loads((out / "private/scenario.json").read_bytes())
    assert scenario["baseline_activity"]["intensity"] == "medium"
    assert scenario["storyline"] == []
    assert not json.loads((out / "reports/qualification.json").read_bytes())["eligible"]
    assert not (out / "public").exists()
    assert not verify_bundle(out).qualified
    with pytest.raises(ValueError, match="Only fully qualified"):
        publish_bundle(out, str(tmp_path / "store"))
    published = publish_bundle(out, str(tmp_path / "store"), diagnostic=True)
    pulled = pull_bundle(published, tmp_path / "retrieved")
    assert not pulled.qualified
    assert not (tmp_path / "store/latest.json").exists()


def generation_backend(*, fail=None, quality='{"acceptance_passed": true}', truth='{"events": []}'):
    """Controlled external process; artifacts and exit statuses exercise the real runner."""

    def command(root, *args):
        if args[0] == fail:
            return [sys.executable, "-c", "raise SystemExit(7)"]
        if args[0] == "generate":
            target = args[args.index("--output") + 1]
            seed = args[args.index("--seed") + 1] if "--seed" in args else "unspecified"
            code = (
                f"from pathlib import Path; p=Path({target!r}); p.mkdir(parents=True); "
                f"(p/'used-seed.txt').write_text({seed!r}); "
            )
            if truth is not None:
                code += f"(p/'GROUND_TRUTH.json').write_text({truth!r})"
        elif args[0] == "eval":
            code = f"print({quality!r})"
        else:
            code = "pass"
        return [sys.executable, "-c", code]

    return command


def setup_generation(tmp_path, scenario_seed=None):
    backend = checkout(tmp_path / "backend")
    source = tmp_path / "source.json"
    data = {"name": "ambient", "storyline": []}
    if scenario_seed is not None:
        data["generation_seed"] = scenario_seed
    source.write_text(json.dumps(data))
    return source, tmp_path / "out", dict(backend=backend, pin=inspect_backend(backend))


def test_backend_quality_is_recorded_without_claiming_native_qualification(tmp_path):
    source, out, kwargs = setup_generation(tmp_path)
    generate_scenario(source, out, command_factory=generation_backend(), **kwargs)
    status = json.loads((out / "reports/generation.json").read_bytes())
    assert status["status"] == "succeeded"
    assert status["backend_passed"] is True
    assert [s["stage"] for s in status["stages"]] == ["validate", "generate", "quality"]
    assert not verify_bundle(out).qualified
    assert (out / "private/native/GROUND_TRUTH.json").read_text() == '{"events": []}'


@pytest.mark.parametrize(
    "quality",
    [
        '{"acceptance_passed": false, "overall_score": 100}',
        '{"acceptance_passed": "true"}',
        '{"overall_score": 100}',
        "not json",
    ],
)
def test_quality_rejection_or_malformed_report_retains_diagnostic_bundle(tmp_path, quality):
    source, out, kwargs = setup_generation(tmp_path)
    with pytest.raises((ValueError, RuntimeError)):
        generate_scenario(
            source, out, command_factory=generation_backend(quality=quality), **kwargs
        )
    status = json.loads((out / "reports/generation.json").read_bytes())
    assert status["status"] == "failed" and status["error"]
    assert status["phase"] == "quality"
    assert status["backend_passed"] is not True
    assert not verify_bundle(out).qualified
    assert (out / "reports/stages/quality.stdout").read_text().strip() == quality
    assert publish_bundle(out, str(tmp_path / "store"), diagnostic=True)


@pytest.mark.parametrize(
    "failed,phase,stages",
    [
        ("validate", "validate", 1),
        ("generate", "generate", 2),
        ("eval", "quality", 3),
    ],
)
def test_failed_stage_is_sealed_and_later_stages_are_not_run(tmp_path, failed, phase, stages):
    source, out, kwargs = setup_generation(tmp_path)
    with pytest.raises(RuntimeError, match="exit 7"):
        generate_scenario(source, out, command_factory=generation_backend(fail=failed), **kwargs)
    status = json.loads((out / "reports/generation.json").read_bytes())
    assert status["status"] == "failed" and status["phase"] == phase
    assert len(status["stages"]) == stages
    assert status["stages"][-1]["exit"] == 7
    assert not verify_bundle(out).qualified
    published = publish_bundle(out, str(tmp_path / "store"), diagnostic=True)
    assert not pull_bundle(published, tmp_path / "retrieved").qualified
    assert not (tmp_path / "store/latest.json").exists()


@pytest.mark.parametrize(
    "scenario_seed,override,expected", [(None, None, 42), (17, None, 17), (17, 0, 0)]
)
def test_effective_seed_is_recorded_and_sent_to_backend(
    tmp_path, scenario_seed, override, expected
):
    source, out, kwargs = setup_generation(tmp_path, scenario_seed)
    generate_scenario(source, out, seed=override, command_factory=generation_backend(), **kwargs)
    assert json.loads((out / "sources/generation.json").read_bytes())["seed"] == expected
    assert (out / "private/native/used-seed.txt").read_text() == str(expected)


def test_seed_outside_backend_uint64_range_is_rejected_before_build(tmp_path):
    source, out, kwargs = setup_generation(tmp_path)
    with pytest.raises(ValueError):
        generate_scenario(source, out, seed=2**64, command_factory=generation_backend(), **kwargs)
    assert not out.exists()


@pytest.mark.parametrize("truth", [None, "invalid json"])
def test_missing_or_malformed_native_truth_retains_failure(tmp_path, truth):
    source, out, kwargs = setup_generation(tmp_path)
    with pytest.raises((OSError, ValueError)):
        generate_scenario(source, out, command_factory=generation_backend(truth=truth), **kwargs)
    status = json.loads((out / "reports/generation.json").read_bytes())
    assert status["status"] == "failed" and status["phase"] == "annotate"
    assert not verify_bundle(out).qualified


def test_timeout_is_retained_as_diagnostic_failure(tmp_path):
    source, out, kwargs = setup_generation(tmp_path)

    def command(root, *args):
        return [sys.executable, "-c", "import time; time.sleep(30)"]

    with pytest.raises(RuntimeError, match="exit 124"):
        generate_scenario(source, out, stage_timeout_seconds=1, command_factory=command, **kwargs)
    assert not verify_bundle(out).qualified
    assert json.loads((out / "reports/generation.json").read_bytes())["stages"][0]["exit"] == 124


def test_launch_error_is_recorded_even_without_an_exit_status(tmp_path):
    source, out, kwargs = setup_generation(tmp_path)
    with pytest.raises(OSError):
        generate_scenario(
            source, out, command_factory=lambda *_: [str(tmp_path / "missing-executable")], **kwargs
        )
    status = json.loads((out / "reports/generation.json").read_bytes())
    assert status["status"] == "failed" and status["phase"] == "validate"
    assert status["stages"] == [] and "FileNotFoundError" in status["error"]
    assert not verify_bundle(out).qualified


def test_workload_context_survives_timeout_without_reducing_background(tmp_path):
    source, out, kwargs = setup_generation(tmp_path)
    data = json.loads(source.read_bytes())
    data.update(
        environment={"systems": [{"hostname": f"host-{i}"} for i in range(9)]},
        time_window={"start": "2024-05-27T12:00:00Z", "duration": "30m", "warmup": "1h"},
        baseline_activity={"intensity": "low"},
    )
    source.write_text(json.dumps(data))
    with pytest.raises(RuntimeError):
        generate_scenario(
            source, out, command_factory=generation_backend(fail="generate"), **kwargs
        )
    workload = json.loads((out / "reports/workload.json").read_bytes())
    assert workload["configured_systems"] == 9
    assert workload["authored_events"] == 0
    assert workload["declared_time_window"] == data["time_window"]
    assert workload["declared_baseline_activity"] == {"intensity": "low"}
    assert (
        json.loads((out / "private/scenario.json").read_bytes())["time_window"]
        == data["time_window"]
    )
