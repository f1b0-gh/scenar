"""Bounded real-backend smoke matrix, with verified disk and optional S3 delivery."""

from pathlib import Path
from typing import Literal

from pydantic import Field

from ..backend import BackendIdentity, active_pin, backend_command, backend_path
from ..bundle import Model
from ..io import write_json
from ..storage import publish_bundle, pull_bundle
from .matrix import DatasetSpec, prepare_dataset, run_dataset
from .visibility import VisibilitySettings


class SmokeReport(Model):
    schema_id: Literal["scenar/dataset-smoke/v1"] = Field(
        default="scenar/dataset-smoke/v1", alias="schema"
    )
    passed: bool = Field(default=False, strict=True)
    planned: int = Field(default=0, strict=True)
    qualified: int = Field(default=0, strict=True)
    disk_roundtrip: bool = Field(default=False, strict=True)
    s3_roundtrip: bool | None = Field(default=None, strict=True)
    errors: list[str] = Field(default_factory=list)


def smoke_specs(timeout: int) -> list[DatasetSpec]:
    options = dict(
        variants=["benign", "malicious"],
        sizes=["small"],
        seeds=[9501],
        stage_timeout_seconds=timeout,
        visibility_application="derived",
    )
    return [
        DatasetSpec(
            families=[
                "inventory_archive",
                "remote_access",
                "persistence",
                "credential_access",
                "c2",
            ],
            **options,
        ),
        DatasetSpec(
            families=["inventory_archive"],
            visibility=[
                VisibilitySettings(mode="lossy", probability=0.2, hosts=["FILE-01"]),
                VisibilitySettings(mode="delayed", delay_us=60000000, hosts=["FILE-01"]),
                VisibilitySettings(mode="missing_endpoint", hosts=["FILE-01"]),
            ],
            **options,
        ),
    ]


def run_smoke(
    output: Path,
    *,
    backend: Path | None = None,
    pin: BackendIdentity | None = None,
    s3_store: str | None = None,
    stage_timeout_seconds: int = 1800,
    command_factory=backend_command,
    check_readiness: bool = True,
    progress=None,
) -> SmokeReport:
    if s3_store is not None and not s3_store.startswith("s3://"):
        raise ValueError("Smoke S3 store must be an s3:// URI")
    specs = smoke_specs(stage_timeout_seconds)
    root = backend_path(backend)
    pin = pin or active_pin()
    output.mkdir(parents=True, exist_ok=False)
    report = SmokeReport(
        planned=sum(len(s.dimensions_list()) for s in specs),
        s3_roundtrip=False if s3_store else None,
    )
    try:
        if check_readiness:
            from .diagnostics import preflight

            readiness = preflight(root, pin, output)
            write_json(output / "preflight.json", readiness.model_dump(mode="json", by_alias=True))
            if not readiness.ready:
                raise ValueError("Backend preflight failed; see preflight.json")
        for index, spec in enumerate(specs):
            run = output / f"matrix-{index}"
            prepare_dataset(spec, run, backend=root, pin=pin)
            result = run_dataset(
                run, backend=root, command_factory=command_factory, progress=progress
            )
            report.qualified += result["qualified"]
            if result["qualified"] != result["planned"]:
                report.errors.append(
                    f"matrix-{index}: {result['qualified']}/{result['planned']} qualified"
                )
                continue
            uri = publish_bundle(run, str(output / "disk-store"))
            pulled = pull_bundle(uri, output / f"disk-pull-{index}")
            if not pulled.qualified:
                raise ValueError("Disk roundtrip lost qualification")
            if s3_store:
                uri = publish_bundle(run, s3_store)
                pulled = pull_bundle(uri, output / f"s3-pull-{index}")
                if not pulled.qualified:
                    raise ValueError("S3 roundtrip lost qualification")
        report.disk_roundtrip = not report.errors
        if s3_store:
            report.s3_roundtrip = not report.errors
        report.passed = not report.errors and report.qualified == report.planned
    except Exception as exc:
        report.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        write_json(output / "report.json", report.model_dump(mode="json", by_alias=True))
    return report
