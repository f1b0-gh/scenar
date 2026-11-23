"""Library entry point for synthetic Forge generation, including ambient-only captures."""

import hashlib
import json
import uuid
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue

from .attack import Model
from .authoring import build
from .backend import BackendIdentity, active_pin, backend_command, backend_path, check_backend
from .background import BackgroundActivity
from .bundle import Artifact, BundleManifest, Capture, QualityReport, Stage
from .io import canonical, digest, files, write_json
from .runner import execute
from .scenario import authored_cardinality
from .truth import GroundTruth, annotate_native_truth


class GenerationOptions(Model):
    seed: int | None = Field(default=None, strict=True, ge=0, le=2**64 - 1)
    stage_timeout_seconds: int = Field(default=300, strict=True, ge=1)


class GenerationStatus(Model):
    schema_version: Literal["scenar/generation-status/v1"] = "scenar/generation-status/v1"
    status: Literal["running", "succeeded", "failed"] = "running"
    phase: Literal["configure", "validate", "generate", "quality", "annotate", "complete"] = (
        "configure"
    )
    stages: list[Stage] = Field(default_factory=list)
    backend_passed: bool | None = Field(default=None, strict=True)
    error: str | None = None


class WorkloadSummary(Model):
    schema_version: Literal["scenar/generation-workload/v1"] = "scenar/generation-workload/v1"
    configured_systems: int
    authored_steps: int
    authored_events: int
    declared_time_window: dict[str, JsonValue]
    declared_baseline_activity: dict[str, JsonValue]
    note: str = (
        "Configuration inventory, not a runtime or event-volume estimate. Background and "
        "warm-up work extend beyond authored events. Omitted settings use backend defaults."
    )


def _seal_generation(output: Path, noise_only: bool) -> None:
    manifest = BundleManifest(
        bundle_id=uuid.uuid4().hex,
        captures=[
            Capture(
                id="raw",
                family="ambient" if noise_only else "authored",
                qualified=False,
                source_sha256=hashlib.sha256(
                    canonical(files(output / "private/native"))
                ).hexdigest(),
            )
        ],
        files=[
            Artifact(path=name, sha256=sha, size=(output / name).stat().st_size)
            for name, sha in files(output).items()
            if name != "manifest.json"
        ],
    )
    write_json(output / "manifest.json", manifest.model_dump(mode="json", by_alias=True))


def generate_scenario(
    source: Path,
    output: Path,
    *,
    backend: Path | None = None,
    pin: BackendIdentity | None = None,
    background: BackgroundActivity | None = None,
    ground_truth: GroundTruth | None = None,
    noise_only: bool = False,
    seed: int | None = None,
    catalog_path: Path | None = None,
    overrides: list[str] | None = None,
    stage_timeout_seconds: int = 300,
    command_factory=backend_command,
) -> Path:
    options = GenerationOptions(seed=seed, stage_timeout_seconds=stage_timeout_seconds)
    root = backend_path(backend)
    pin = pin or active_pin()
    check_backend(root, pin)
    scenario = build(
        source,
        output,
        overrides,
        catalog_path=catalog_path,
        background=background,
        ground_truth=ground_truth,
        noise_only=noise_only,
    )
    write_json(output / "sources/backend.json", pin.model_dump(mode="json"))
    folder = output / "reports/stages"
    folder.mkdir(parents=True)
    status = GenerationStatus()
    try:
        declared = json.loads(scenario.read_bytes())
        # The pinned backend defaults generation_seed to 42. Always make the chosen
        # seed explicit so future backend defaults cannot alter this invocation.
        effective_seed = (
            options.seed if options.seed is not None else declared.get("generation_seed", 42)
        )
        options = GenerationOptions(
            seed=effective_seed, stage_timeout_seconds=options.stage_timeout_seconds
        )
        if options.seed is None:
            raise ValueError("Scenario generation_seed cannot be null")
        write_json(output / "sources/generation.json", options.model_dump())
        counts = authored_cardinality(declared)
        workload = WorkloadSummary(
            configured_systems=len(declared.get("environment", {}).get("systems", [])),
            authored_steps=len(counts),
            authored_events=sum(counts.values()),
            declared_time_window=declared.get("time_window", {}),
            declared_baseline_activity=declared.get("baseline_activity", {}),
        )
        write_json(output / "reports/workload.json", workload.model_dump(mode="json"))
        native = output / "private/native"
        for name, args in (
            ("validate", ["validate", str(scenario.resolve())]),
            (
                "generate",
                [
                    "generate",
                    str(scenario.resolve()),
                    "--output",
                    str(native.resolve()),
                    "--seed",
                    str(options.seed),
                ],
            ),
            ("quality", ["eval", str(native.resolve()), "--format", "json"]),
        ):
            status.phase = name
            write_json(output / "reports/generation.json", status.model_dump(mode="json"))
            stage = execute(
                command_factory(root, *args), folder, name, options.stage_timeout_seconds, root
            )
            status.stages.append(stage)
            write_json(
                output / "reports/execution.json",
                {"stages": [s.model_dump() for s in status.stages]},
            )
            if stage.exit:
                limit = (
                    f" (stage limit {options.stage_timeout_seconds}s; adjust stage_timeout_seconds "
                    "or --stage-timeout-seconds and any caller deadline)"
                    if stage.exit == 124
                    else ""
                )
                raise RuntimeError(
                    f"Backend {name} failed with exit {stage.exit}{limit}; logs retained in {folder}"
                )
            if name == "quality":
                quality = QualityReport.model_validate_json(
                    (folder / "quality.stdout").read_bytes()
                )
                status.backend_passed = quality.acceptance_passed
                if not quality.acceptance_passed:
                    raise RuntimeError(
                        f"Backend quality rejected generated data; see {folder / 'quality.stdout'}"
                    )
        status.phase = "annotate"
        write_json(output / "reports/generation.json", status.model_dump(mode="json"))
        native_truth = native / "GROUND_TRUTH.json"
        selected = GroundTruth.model_validate_json(
            (output / "private/ground-truth.json").read_bytes()
        )
        overlay = annotate_native_truth(
            json.loads(native_truth.read_bytes()), selected, authored_counts=counts
        )
        overlay.update(source_sha256=digest(native_truth), eligible=False)
        write_json(output / "private/scenar-ground-truth.json", overlay)
        status.status, status.phase = "succeeded", "complete"
    except Exception as exc:
        # Keep ordinary launch, execution, parsing and annotation failures inspectable
        # without converting them into successful generation or swallowing the error.
        status.status = "failed"
        status.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        write_json(output / "reports/generation.json", status.model_dump(mode="json"))
        write_json(
            output / "reports/execution.json", {"stages": [s.model_dump() for s in status.stages]}
        )
        write_json(
            output / "reports/qualification.json",
            {
                "eligible": False,
                "backend_passed": status.backend_passed,
                "reason": status.error
                or "Raw generation only; native evidence audits are required before qualification or promotion",
            },
        )
        from .datasets.diagnostics import measure_generation

        write_json(
            output / "reports/measurements.json",
            measure_generation(output, status).model_dump(mode="json", by_alias=True),
        )
        _seal_generation(output, noise_only)
    return output
