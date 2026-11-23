"""Upstream candidate checks never mutate the active backend pin."""

import json
import subprocess
from pathlib import Path

from .backend import compare_backends, inspect_backend
from .io import write_json
from .runner import prepare_run, run_all


def export_schema(checkout: Path) -> dict:
    code = "import json; from evidenceforge.models.scenario import Scenario; print(json.dumps(Scenario.model_json_schema(), sort_keys=True))"
    process = subprocess.run(
        ["uv", "run", "--locked", "--project", str(checkout), "python", "-c", code],
        cwd=checkout,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if process.returncode:
        raise ValueError("Backend schema export failed: " + process.stderr.strip())
    return json.loads(process.stdout)


def compare_schemas(before: dict, after: dict) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {"added": [], "removed": [], "changed": []}

    def visit(a, b, path):
        if isinstance(a, dict) and isinstance(b, dict):
            result["removed"].extend(path + k for k in sorted(a.keys() - b.keys()))
            result["added"].extend(path + k for k in sorted(b.keys() - a.keys()))
            for key in sorted(a.keys() & b.keys()):
                visit(a[key], b[key], path + key + ".")
        elif a != b:
            result["changed"].append(path.rstrip("."))

    visit(before, after, "")
    return result


def check_candidate(active: Path, candidate: Path, destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=False)
    report = compare_backends(active, candidate)
    report["schema_changes"] = compare_schemas(export_schema(active), export_schema(candidate))
    # A bounded subset includes benign controls and ambiguous shared-parent workflows.
    for name, checkout in (("active", active), ("candidate", candidate)):
        run = destination / name
        prepare_run(
            "investigation-episodes",
            run,
            backend=checkout,
            families=("benign_only", "independent_shared_parent"),
            pin=inspect_backend(checkout),
        )
        summary = run_all(run, backend=checkout)
        report[name + "_matrix"] = {
            k: v for k, v in summary.items() if k not in ("attempts", "results")
        }
    report["compatible"] = all(
        report[name + "_matrix"]["execution_complete"] for name in ("active", "candidate")
    )
    report["note"] = (
        "Qualification matrix only; review schema/behavior differences before explicitly updating a pin."
    )
    write_json(destination / "compatibility.json", report)
    return report
