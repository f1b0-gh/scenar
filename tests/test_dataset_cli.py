import json

from scenar.cli import main
from scenar.datasets import matrix
from tests.test_datasets import observed_dataset, prepare
from tests.test_generation import generation_backend


def test_resume_cli_preserves_json_stdout_and_reports_progress_on_stderr(
    tmp_path, monkeypatch, capsys
):
    from scenar.datasets import resume

    run, backend, _ = prepare(tmp_path)
    matrix.run_dataset(run, backend=backend, command_factory=generation_backend())
    original = resume.resume_dataset
    monkeypatch.setattr(
        resume,
        "resume_dataset",
        lambda *a, **kw: original(*a, **kw, command_factory=generation_backend()),
    )
    assert (
        main(
            [
                "dataset",
                "resume",
                str(run),
                "--output",
                str(tmp_path / "new"),
                "--backend",
                str(backend),
            ]
        )
        == 1
    )  # Empty fixture telemetry remains unqualified.
    output = capsys.readouterr()
    assert json.loads(output.out)["reused"] == 2
    assert "reused" in output.err and "[2/2]" in output.err


def test_lineage_and_split_cli_return_valid_json_and_fail_on_leakage(tmp_path, monkeypatch, capsys):
    run, plan, _ = observed_dataset(tmp_path, monkeypatch)
    assert main(["dataset", "lineage", str(run)]) == 0
    assert json.loads(capsys.readouterr().out)["restricted"] is True
    assignments = tmp_path / "splits.json"
    assignments.write_text(
        json.dumps(
            {
                "schema": "scenar/dataset-splits/v1",
                "assignments": [
                    {
                        "run": str(run),
                        "case_id": c.id,
                        "partition": "development" if i == 0 else "test",
                        "exposed": False,
                    }
                    for i, c in enumerate(plan.cases)
                ],
            }
        )
    )
    assert main(["dataset", "check-splits", str(assignments)]) == 2
    assert "crosses partitions" in capsys.readouterr().err


def test_preflight_cli_reports_missing_runtime_before_generation(tmp_path, capsys):
    run, backend, _ = prepare(tmp_path)
    assert main(["dataset", "preflight", str(run), "--backend", str(backend)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert not report["ready"]
    assert not (run / "reports/dataset-started.json").exists()
