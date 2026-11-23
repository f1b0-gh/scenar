"""Read-only host readiness and measurements from verified generation artifacts."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Literal

from pydantic import Field

from ..backend import BackendIdentity, check_backend
from ..bundle import Model, Stage
from ..generation import GenerationStatus
from ..io import canonical, files
from ..replay import verify_bundle


class ReadinessCheck(Model):
    name: str
    status: Literal["passed", "failed", "unknown"]
    detail: str


class PreflightReport(Model):
    schema_id: Literal["scenar/preflight/v1"] = Field(default="scenar/preflight/v1", alias="schema")
    ready: bool = Field(strict=True)
    checks: list[ReadinessCheck]
    free_bytes: int = Field(strict=True, ge=0)
    note: str = "Readiness checks are not proof of native generation or a runtime estimate."


def check_spool_ancestry(
    path: Path,
    *,
    uid: int,
    stat_path: Callable = Path.lstat,
) -> ReadinessCheck:
    """Mirror revision 162 POSIX ownership checks without creating or changing paths."""
    current = Path(os.path.abspath(path))
    while True:
        info = stat_path(current)
        if not stat.S_ISDIR(info.st_mode):
            return ReadinessCheck(
                name="spool_ancestry",
                status="failed",
                detail=f"{current}: expected directory without symlinks",
            )
        if info.st_uid not in {0, uid}:
            return ReadinessCheck(
                name="spool_ancestry",
                status="failed",
                detail=f"{current}: must be root- or process-owned",
            )
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            return ReadinessCheck(
                name="spool_ancestry",
                status="failed",
                detail=f"{current}: shared writable ancestor requires sticky mode",
            )
        if current == current.parent:
            return ReadinessCheck(
                name="spool_ancestry",
                status="passed",
                detail="Existing spool ancestors satisfy pinned POSIX checks",
            )
        current = current.parent


def _existing_parent(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    while not path.exists() and not path.is_symlink():
        path = path.parent
    return path


def preflight(
    backend: Path,
    pin: BackendIdentity,
    output: Path,
    *,
    min_free_bytes: int = 0,
) -> PreflightReport:
    if type(min_free_bytes) is not int or min_free_bytes < 0:
        raise ValueError("min_free_bytes must be a nonnegative integer")
    checks = []
    identity_ok = False
    try:
        check_backend(backend, pin)
        identity_ok = True
        checks.append(
            ReadinessCheck(name="backend_identity", status="passed", detail="Matches selected pin")
        )
    except (OSError, ValueError, KeyError) as exc:
        checks.append(ReadinessCheck(name="backend_identity", status="failed", detail=str(exc)))
    checks.append(
        ReadinessCheck(
            name="uv",
            status="passed" if shutil.which("uv") else "failed",
            detail="uv is on PATH" if shutil.which("uv") else "Install uv on the execution host",
        )
    )
    interpreter = backend / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if identity_ok and interpreter.exists():
        try:
            result = subprocess.run(
                [
                    str(interpreter),
                    "-I",
                    "-B",
                    "-c",
                    "import evidenceforge; import sys; assert sys.version_info >= (3, 12)",
                ],
                cwd=backend,
                capture_output=True,
                timeout=15,
            )
            checks.append(
                ReadinessCheck(
                    name="backend_runtime",
                    status="passed" if result.returncode == 0 else "failed",
                    detail="Backend interpreter/import probe passed"
                    if result.returncode == 0
                    else "Backend interpreter/import failed; run uv sync --locked in the backend checkout",
                )
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append(ReadinessCheck(name="backend_runtime", status="failed", detail=str(exc)))
    else:
        checks.append(
            ReadinessCheck(
                name="backend_runtime",
                status="failed",
                detail="Verify pin and run uv sync --locked in the backend checkout before generation",
            )
        )
    spool = _existing_parent(
        Path(os.environ.get("EFORGE_SPOOL_DIR", tempfile.gettempdir())).expanduser()
    )
    if os.name == "posix" and pin.behavior_revision == 162:
        try:
            checks.append(check_spool_ancestry(spool, uid=os.geteuid()))
        except OSError as exc:
            checks.append(ReadinessCheck(name="spool_ancestry", status="failed", detail=str(exc)))
    else:
        checks.append(
            ReadinessCheck(
                name="spool_ancestry",
                status="unknown",
                detail="No read-only ancestry adapter for this backend/platform",
            )
        )
    parent = _existing_parent(output)
    free = shutil.disk_usage(parent).free
    writable = os.access(parent, os.W_OK | os.X_OK)
    checks.append(
        ReadinessCheck(
            name="output_storage",
            status="passed" if writable and free >= min_free_bytes else "failed",
            detail=f"{free} free bytes; requested minimum {min_free_bytes}; writable={writable}",
        )
    )
    return PreflightReport(
        ready=all(c.status == "passed" for c in checks), checks=checks, free_bytes=free
    )


class GenerationMeasurements(Model):
    schema_id: Literal["scenar/generation-measurements/v1"] = Field(
        default="scenar/generation-measurements/v1", alias="schema"
    )
    status: Literal["running", "succeeded", "failed"]
    workload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    backend_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    stages: list[Stage]
    native_files: int = Field(strict=True, ge=0)
    native_bytes: int = Field(strict=True, ge=0)


def measure_generation(output: Path, status: GenerationStatus) -> GenerationMeasurements:
    scenario = json.loads((output / "private/scenario.json").read_bytes())
    scenario.pop("generation_seed", None)
    backend = BackendIdentity.model_validate_json((output / "sources/backend.json").read_bytes())
    native = output / "private/native"
    inventory = files(native)
    return GenerationMeasurements(
        status=status.status,
        workload_sha256=hashlib.sha256(canonical(scenario)).hexdigest(),
        backend_sha256=backend.source_sha256,
        stages=status.stages,
        native_files=len(inventory),
        native_bytes=sum((native / n).stat().st_size for n in inventory),
    )


def _measurement(root: Path) -> tuple[str, GenerationMeasurements]:
    manifest = verify_bundle(root)
    status = GenerationStatus.model_validate_json((root / "reports/generation.json").read_bytes())
    recorded = GenerationMeasurements.model_validate_json(
        (root / "reports/measurements.json").read_bytes()
    )
    actual = measure_generation(root, status)
    if actual != recorded:
        raise ValueError("Generation measurements differ from source artifacts")
    return manifest.bundle_id, actual


def timing_report(reference: Path, histories: list[Path]) -> dict:
    _, baseline = _measurement(reference)
    samples = []
    failed = incomparable = 0
    failed_stages = []
    seen = set()
    for source in histories:
        if (source / "dataset.json").exists():
            from .matrix import load_dataset

            verify_bundle(source)
            roots = [source / "private/attempts" / c.id for c in load_dataset(source).cases]
        else:
            roots = [source]
        for root in roots:
            identity, measurement = _measurement(root)
            if identity in seen:
                continue
            seen.add(identity)
            if (measurement.workload_sha256, measurement.backend_sha256) != (
                baseline.workload_sha256,
                baseline.backend_sha256,
            ):
                incomparable += 1
            elif measurement.status != "succeeded" or any(s.exit for s in measurement.stages):
                failed += 1
                failed_stages.extend(
                    {"stage": s.stage, "exit": s.exit, "elapsed_seconds": s.elapsed_seconds}
                    for s in measurement.stages
                    if s.exit
                )
            else:
                samples.append(measurement)
    stages = {}
    for name in sorted({stage.stage for m in samples for stage in m.stages}):
        values = [s.elapsed_seconds for m in samples for s in m.stages if s.stage == name]
        stages[name] = {
            "samples": len(values),
            "min_seconds": min(values),
            "max_seconds": max(values),
        }
    volumes = [m.native_bytes for m in samples]
    return {
        "schema": "scenar/timing-report/v1",
        "comparable_successes": len(samples),
        "failed_samples": failed,
        "incomparable_samples": incomparable,
        "failed_stages": failed_stages,
        "stages": stages,
        "native_bytes": {"min": min(volumes), "max": max(volumes)} if volumes else None,
        "note": "Observed ranges for identical scenario configuration excluding seed and identical backend source. "
        "Host load/hardware may differ; these are not completion guarantees.",
    }
