import json
import subprocess
import sys

from scenar.cli import main


def test_help_exposes_producer_commands_without_a_detect_runtime():
    out = subprocess.run([sys.executable, "-m", "scenar", "--help"], capture_output=True, text=True)
    assert out.returncode == 0
    assert "replay" in out.stdout
    assert "dataset" in out.stdout
    assert "export-public" in out.stdout
    assert "dossier" not in out.stdout


def test_build_yaml_without_nickel_and_refuse_overwrite(tmp_path):
    source = tmp_path / "scenario.yaml"
    source.write_text('name: tiny\ntime_window:\n  start: "2024-01-01T00:00:00Z"\n')
    target = tmp_path / "build"
    assert main(["build", str(source), "--output", str(target)]) == 0
    assert json.loads((target / "private/scenario.json").read_text())["name"] == "tiny"
    assert main(["build", str(source), "--output", str(target)]) != 0


def test_missing_nickel_reports_optional_dependency(tmp_path, monkeypatch, capsys):
    source = tmp_path / "main.ncl"
    source.write_text("{}")
    monkeypatch.setenv("PATH", "")
    assert main(["build", str(source), "--output", str(tmp_path / "build")]) != 0
    assert "Nickel" in capsys.readouterr().err


def test_generate_cli_timeout_reaches_runner_and_returns_failure(tmp_path, monkeypatch, capsys):
    import scenar.generation as generation
    from tests.test_generation import setup_generation

    source, out, kwargs = setup_generation(tmp_path)
    pin = tmp_path / "pin.json"
    pin.write_text(kwargs["pin"].model_dump_json())
    original = generation.generate_scenario

    def command(root, *args):
        return [sys.executable, "-c", "import time; time.sleep(30)"]

    def generate(*args, **options):
        return original(*args, **options, command_factory=command)

    monkeypatch.setattr(generation, "generate_scenario", generate)
    assert (
        main(
            [
                "generate",
                str(source),
                "--output",
                str(out),
                "--backend",
                str(kwargs["backend"]),
                "--pin",
                str(pin),
                "--stage-timeout-seconds",
                "1",
            ]
        )
        == 2
    )
    assert "exit 124" in capsys.readouterr().err
    assert json.loads((out / "sources/generation.json").read_bytes())["stage_timeout_seconds"] == 1
    assert json.loads((out / "reports/generation.json").read_bytes())["status"] == "failed"
