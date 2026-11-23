"""Resume into a new run, preserving prior attempts and frozen provenance."""

import hashlib
import shutil
from pathlib import Path

from ..backend import backend_command, backend_path, check_backend
from ..generation import GenerationStatus
from ..io import canonical, files, write_json
from ..replay import verify_bundle
from .matrix import _check_implementation, load_dataset, run_dataset, verify_capture_inputs


def resume_dataset(
    source: Path,
    output: Path,
    *,
    backend: Path | None = None,
    command_factory=backend_command,
    progress=None,
) -> dict:
    if output.exists():
        raise FileExistsError(output)
    if output.resolve().is_relative_to(source.resolve()):
        raise ValueError("Resume destination must be outside the source run")
    plan = load_dataset(source)
    _check_implementation(source)
    root = backend_path(backend)
    check_backend(root, plan.backend)
    inventory = files(source)
    if (source / "manifest.json").exists():
        verify_bundle(source)
    reused = set()
    for case in plan.cases:
        folder = source / "private/attempts" / case.id
        status = folder / "reports/generation.json"
        if not status.exists():
            continue
        try:
            parsed = GenerationStatus.model_validate_json(status.read_bytes())
        except ValueError:
            continue  # An interrupted status is retained, never reused.
        if parsed.status == "succeeded" and (folder / "manifest.json").exists():
            verify_capture_inputs(source, plan, case)
            reused.add(case.id)
    output.mkdir(parents=True)
    shutil.copytree(source, output / "private/history/previous")
    if files(output / "private/history/previous") != inventory or files(source) != inventory:
        raise ValueError("Source changed while creating resume snapshot")
    for name in ("sources", "private/cases"):
        shutil.copytree(source / name, output / name)
    shutil.copyfile(source / "dataset.json", output / "dataset.json")
    for case in plan.cases:
        if case.id in reused:
            shutil.copytree(
                source / "private/attempts" / case.id,
                output / "private/attempts" / case.id,
            )
    write_json(
        output / "reports/resume.json",
        {
            "schema": "scenar/dataset-resume/v1",
            "parent_sha256": hashlib.sha256(canonical(inventory)).hexdigest(),
            "reused": sorted(reused),
            "previous": "private/history/previous",
        },
    )
    return run_dataset(output, backend=root, command_factory=command_factory, progress=progress)
