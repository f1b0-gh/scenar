"""Frozen synthetic dataset matrices; no detector or investigation execution."""

import hashlib
import itertools
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Self

import yaml
from pydantic import AwareDatetime, Field, StrictInt, model_validator

from ..attack import Model, load_catalog
from ..backend import BackendIdentity, active_pin, backend_command, backend_path, check_backend
from ..background import BackgroundActivity
from ..bundle import Artifact, BundleManifest, Capture
from ..generation import GenerationOptions, GenerationStatus, generate_scenario
from ..io import canonical, digest, files, safe_path, write_json
from ..scenario import ScenarioDocument, authored_cardinality, compile_document
from ..truth import GroundTruth, annotate_native_truth
from .audit import NATIVE_FILENAMES, EffectExpectation, audit_native, collection_window
from .recipes import build_recipe
from .visibility import VisibilitySettings, apply_visibility

Family = Literal["inventory_archive", "remote_access", "persistence", "credential_access", "c2"]
Variant = Literal["normal", "benign", "malicious", "mixed", "ambiguous"]
Size = Literal["small", "medium", "large"]
Pattern = Literal["periodic", "burst", "sparse", "rotating"]
PACKAGE = Path(__file__).parent.parent


class DatasetSpec(Model):
    schema_id: Literal["scenar/dataset/v1"] = Field(default="scenar/dataset/v1", alias="schema")
    families: list[Family] = Field(default_factory=lambda: ["inventory_archive"], min_length=1)
    variants: list[Variant] = Field(
        default_factory=lambda: ["normal", "benign", "malicious", "mixed", "ambiguous"],
        min_length=1,
    )
    sizes: list[Size] = Field(default_factory=lambda: ["small"], min_length=1)
    seeds: list[StrictInt] = Field(default_factory=lambda: [42], min_length=1)
    visibility: list[VisibilitySettings] = Field(
        default_factory=lambda: [VisibilitySettings()], min_length=1
    )
    visibility_application: Literal["backend", "derived"] = "backend"
    visibility_cutoff: AwareDatetime | None = None
    c2_patterns: list[Pattern] = Field(default_factory=lambda: ["periodic"], min_length=1)
    start: AwareDatetime = Field(
        default_factory=lambda: datetime(2024, 5, 27, 12, tzinfo=timezone.utc)
    )
    duration_minutes: int = Field(default=60, ge=30, le=1440, strict=True)
    routine_cycles: int = Field(default=2, ge=1, le=24, strict=True)
    background: BackgroundActivity = Field(
        default_factory=lambda: BackgroundActivity(profile="office", intensity="low")
    )
    stage_timeout_seconds: int = Field(default=300, strict=True, ge=1)

    @model_validator(mode="after")
    def dimensions(self) -> Self:
        if self.visibility_cutoff is not None and self.visibility_application != "derived":
            raise ValueError("visibility_cutoff requires derived visibility")
        for values in (self.families, self.variants, self.sizes, self.seeds, self.c2_patterns):
            if len(values) != len(set(values)):
                raise ValueError("Duplicate dataset matrix dimension")
        if any(seed < 0 or seed > 2**64 - 1 for seed in self.seeds):
            raise ValueError("Dataset seeds must be uint64 values")
        visibility = [canonical(v.model_dump(mode="json")) for v in self.visibility]
        if len(visibility) != len(set(visibility)):
            raise ValueError("Duplicate visibility configuration")
        family_patterns = sum(len(self.c2_patterns) if f == "c2" else 1 for f in self.families)
        count = (
            family_patterns
            * len(self.variants)
            * len(self.sizes)
            * len(self.seeds)
            * len(self.visibility)
        )
        if count > 4096:
            raise ValueError("Dataset matrix exceeds 4096 cases; prepare smaller explicit batches")
        return self

    def dimensions_list(self) -> list[tuple]:
        return [
            (family, variant, size, seed, vi, pattern)
            for family, variant, size, seed, vi in itertools.product(
                self.families, self.variants, self.sizes, self.seeds, range(len(self.visibility))
            )
            for pattern in (self.c2_patterns if family == "c2" else ["periodic"])
        ]


class DatasetCase(Model):
    id: str = Field(pattern=r"^case-[a-f0-9]{24}$")
    family: Family
    variant: Variant
    size: Size
    seed: int = Field(strict=True, ge=0, le=2**64 - 1)
    visibility_index: int = Field(strict=True, ge=0)
    c2_pattern: Pattern
    scenario: str
    expectations: str

    @model_validator(mode="after")
    def paths(self) -> Self:
        for name in (self.scenario, self.expectations):
            safe_path(Path("/__scenar_dataset__"), name)
        return self


class DatasetPlan(Model):
    schema_id: Literal["scenar/dataset-plan/v1"] = Field(
        default="scenar/dataset-plan/v1", alias="schema"
    )
    spec: DatasetSpec
    backend: BackendIdentity
    cases: list[DatasetCase] = Field(min_length=1)
    inputs: dict[str, str]

    @model_validator(mode="after")
    def population(self) -> Self:
        dimensions = [
            (c.family, c.variant, c.size, c.seed, c.visibility_index, c.c2_pattern)
            for c in self.cases
        ]
        if dimensions != self.spec.dimensions_list() or len({c.id for c in self.cases}) != len(
            self.cases
        ):
            raise ValueError("Dataset cases differ from the planned matrix")
        return self


class CaseResult(Model):
    id: str
    generated: bool = False
    backend_passed: bool | None = None
    native_passed: bool = False
    eligible: bool = False
    error: str | None = None


class DatasetProgress(Model):
    schema_id: Literal["scenar/dataset-progress/v1"] = Field(
        default="scenar/dataset-progress/v1", alias="schema"
    )
    case_id: str
    completed: int = Field(strict=True, ge=0)
    planned: int = Field(strict=True, ge=1)
    state: Literal["running", "reused", "qualified", "rejected"]


def read_spec(source: Path) -> DatasetSpec:
    if source.suffix == ".ncl":
        import subprocess

        result = subprocess.run(
            ["nickel", "export", "-f", "json", str(source.resolve())],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode:
            raise ValueError(result.stderr.strip())
        raw = json.loads(result.stdout)
    else:
        raw = yaml.safe_load(source.read_text())
    return DatasetSpec.model_validate(raw)


def _inventory(run: Path) -> dict[str, str]:
    return {
        f"{prefix}/{name}": sha
        for prefix in ("sources", "private/cases")
        for name, sha in files(run / prefix).items()
        if f"{prefix}/{name}" != "sources/dataset-freeze.json"
    }


def prepare_dataset(
    spec: DatasetSpec,
    output: Path,
    *,
    backend: Path | None = None,
    pin: BackendIdentity | None = None,
    catalog_path: Path | None = None,
) -> DatasetPlan:
    if output.exists():
        raise FileExistsError(output)
    pin = pin or active_pin()
    if backend is not None:
        check_backend(backend_path(backend), pin)
    catalog = load_catalog(catalog_path)
    prepared = []
    for dimension in spec.dimensions_list():
        family, variant, size, seed, vi, pattern = dimension
        recipe = build_recipe(
            family,
            variant,
            size,
            start=spec.start,
            duration_minutes=spec.duration_minutes,
            routine_cycles=spec.routine_cycles,
            c2_pattern=pattern,
        )
        document = recipe.document.model_copy(deep=True)
        document.background = spec.background
        treated = apply_visibility(document.evidenceforge, spec.visibility[vi])
        if spec.visibility_application == "backend":
            document.evidenceforge = treated
        document.evidenceforge["generation_seed"] = seed
        compile_document(document, catalog)
        identity = hashlib.sha256(
            canonical([spec.model_dump(mode="json", by_alias=True), dimension])
        ).hexdigest()[:24]
        case = DatasetCase(
            id=f"case-{identity}",
            family=family,
            variant=variant,
            size=size,
            seed=seed,
            visibility_index=vi,
            c2_pattern=pattern,
            scenario=f"private/cases/case-{identity}/scenario.json",
            expectations=f"private/cases/case-{identity}/expectations.json",
        )
        prepared.append((case, document, recipe))
    output.mkdir(parents=True, exist_ok=False)
    for case, document, recipe in prepared:
        write_json(output / case.scenario, document.model_dump(mode="json", by_alias=True))
        write_json(
            output / case.expectations, [e.model_dump(mode="json") for e in recipe.expectations]
        )
        write_json((output / case.scenario).with_name("metadata.json"), recipe.metadata)
    write_json(output / "sources/spec.json", spec.model_dump(mode="json", by_alias=True))
    write_json(output / "sources/attack/catalog.json", catalog.model_dump(mode="json"))
    write_json(
        output / "sources/attack/pin.json",
        {"catalog_sha256": catalog.sha256, "source_sha256": catalog.source_sha256},
    )
    shutil.copytree(
        PACKAGE,
        output / "sources/scenar",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    plan = DatasetPlan(
        spec=spec, backend=pin, cases=[c for c, _, _ in prepared], inputs=_inventory(output)
    )
    write_json(output / "dataset.json", plan.model_dump(mode="json", by_alias=True))
    write_json(
        output / "sources/dataset-freeze.json", {"plan_sha256": digest(output / "dataset.json")}
    )
    return plan


def load_dataset(run: Path) -> DatasetPlan:
    freeze = json.loads((run / "sources/dataset-freeze.json").read_bytes())
    if digest(run / "dataset.json") != freeze["plan_sha256"]:
        raise ValueError("Frozen dataset plan changed")
    plan = DatasetPlan.model_validate_json((run / "dataset.json").read_bytes())
    if _inventory(run) != plan.inputs:
        raise ValueError("Frozen dataset inputs changed")
    return plan


def _telemetry(native: Path) -> dict[str, str]:
    return {
        name: sha
        for name, sha in files(native).items()
        if name.startswith("data/") and Path(name).name in NATIVE_FILENAMES
    }


def _capture_digest(native: Path) -> str:
    return hashlib.sha256(canonical(files(native))).hexdigest()


def _check_implementation(run: Path) -> None:
    if files(PACKAGE) != files(run / "sources/scenar"):
        raise ValueError(
            "Current implementation differs from frozen dataset sources; prepare a new dataset"
        )


def _view_cutoff(plan: DatasetPlan, scenario: dict) -> datetime:
    if plan.spec.visibility_cutoff is not None:
        return plan.spec.visibility_cutoff
    return collection_window(scenario)[1]


def verify_dataset_public(run: Path) -> None:
    plan = load_dataset(run)
    expected = {}
    for case in plan.cases:
        native = run / "private/attempts" / case.id / "private/native"
        if native.exists():
            if plan.spec.visibility_application == "derived":
                from .views import VisibilityReceipt, derive_view

                scenario = json.loads(
                    (run / "private/attempts" / case.id / "private/scenario.json").read_bytes()
                )
                _, receipt = derive_view(
                    native,
                    scenario,
                    plan.spec.visibility[case.visibility_index],
                    seed=case.seed,
                    cutoff=_view_cutoff(plan, scenario),
                )
                recorded = VisibilityReceipt.model_validate_json(
                    (run / "reports/visibility" / f"{case.id}.json").read_bytes()
                )
                if receipt != recorded:
                    raise ValueError("Dataset visibility receipt changed")
                expected.update(
                    {
                        f"{receipt.view_id}/{name}": sha
                        for name, sha in receipt.output_hashes.items()
                    }
                )
            else:
                identity = _capture_digest(native)
                expected.update(
                    {f"{identity}/{name}": sha for name, sha in _telemetry(native).items()}
                )
    if files(run / "public") != expected:
        raise ValueError("Dataset public export differs from allowlisted native telemetry")


def _seal(run: Path, plan: DatasetPlan, results: list[CaseResult]) -> BundleManifest:
    manifest = BundleManifest(
        bundle_id=uuid.uuid4().hex,
        parent_sha256=(
            json.loads((run / "reports/resume.json").read_bytes())["parent_sha256"]
            if (run / "reports/resume.json").exists()
            else None
        ),
        captures=[
            Capture(
                id=case.id,
                family=case.family,
                qualified=result.eligible,
                source_sha256=_capture_digest(
                    run / "private/attempts" / case.id / "private/native"
                ),
            )
            for case, result in zip(plan.cases, results, strict=True)
        ],
        files=[
            Artifact(path=name, sha256=sha, size=(run / name).stat().st_size)
            for name, sha in files(run).items()
            if name != "manifest.json"
        ],
    )
    write_json(run / "manifest.json", manifest.model_dump(mode="json", by_alias=True))
    return manifest


def run_dataset(
    run: Path,
    *,
    backend: Path | None = None,
    command_factory=backend_command,
    progress: Callable[[DatasetProgress], None] | None = None,
) -> dict:
    plan = load_dataset(run)
    _check_implementation(run)
    root = backend_path(backend)
    check_backend(root, plan.backend)
    if (run / "reports/dataset-started.json").exists() or (run / "manifest.json").exists():
        raise ValueError("Dataset run already started; use a fresh prepared directory")
    marker = run / "reports/dataset-started.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    with marker.open("x") as stream:
        json.dump({"planned": len(plan.cases)}, stream)
    results = []
    reused = 0

    def notify(case: DatasetCase, state: str) -> None:
        if progress is not None:
            progress(
                DatasetProgress(
                    case_id=case.id, completed=len(results), planned=len(plan.cases), state=state
                )
            )

    for case in plan.cases:
        folder = run / "private/attempts" / case.id
        result = CaseResult(id=case.id)
        notify(case, "running")
        try:
            if folder.exists():
                verify_capture_inputs(run, plan, case)
                reused += 1
                notify(case, "reused")
            else:
                generate_scenario(
                    run / case.scenario,
                    folder,
                    backend=root,
                    pin=plan.backend,
                    seed=case.seed,
                    catalog_path=run / "sources/attack",
                    stage_timeout_seconds=plan.spec.stage_timeout_seconds,
                    command_factory=command_factory,
                )
            result.generated = True
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        status = folder / "reports/generation.json"
        if status.exists():
            try:
                parsed = GenerationStatus.model_validate_json(status.read_bytes())
                result.backend_passed = parsed.backend_passed
                if parsed.status != "succeeded" and result.generated:
                    result.generated = False
                    result.error = parsed.error or "Generation did not succeed"
            except (ValueError, OSError) as exc:
                result.generated = False
                result.error = result.error or f"Invalid generation status: {exc}"
        elif result.generated:
            result.generated = False
            result.error = "Missing generation status"
        native = folder / "private/native"
        if native.exists():
            try:
                expectations = [
                    EffectExpectation.model_validate(e)
                    for e in json.loads((run / case.expectations).read_bytes())
                ]
                scenario = json.loads((folder / "private/scenario.json").read_bytes())
                audit = audit_native(native, scenario, expectations)
                write_json(
                    run / "reports/audits" / f"{case.id}.json", audit.model_dump(mode="json")
                )
                result.native_passed = audit.passed
                # Derived views retain original audited native bytes in restricted storage.
                if plan.spec.visibility_application == "derived":
                    from .views import derive_view

                    outputs, receipt = derive_view(
                        native,
                        scenario,
                        plan.spec.visibility[case.visibility_index],
                        seed=case.seed,
                        cutoff=_view_cutoff(plan, scenario),
                    )
                    write_json(
                        run / "reports/visibility" / f"{case.id}.json",
                        receipt.model_dump(mode="json"),
                    )
                    for name, payload in outputs.items():
                        target = safe_path(run, f"public/{receipt.view_id}/{name}")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(payload)
                else:
                    capture = _capture_digest(native)
                    for name in _telemetry(native):
                        target = safe_path(run, f"public/{capture}/{name}")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(safe_path(native, name), target)
            except Exception as exc:
                result.error = result.error or f"Native audit/export: {type(exc).__name__}: {exc}"
        result.eligible = (
            result.generated
            and result.backend_passed is True
            and result.native_passed
            and result.error is None
        )
        results.append(result)
        notify(case, "qualified" if result.eligible else "rejected")
        write_json(run / "reports/attempts" / f"{case.id}.json", result.model_dump(mode="json"))
    report = {
        "schema": "scenar/dataset-report/v1",
        "planned": len(plan.cases),
        "attempted": len(results),
        "reused": reused,
        "generated": sum(r.generated for r in results),
        "qualified": sum(r.eligible for r in results),
        "distinct_native_captures": len(
            {
                _capture_digest(run / "private/attempts" / r.id / "private/native")
                for r in results
                if r.generated
            }
        ),
        "execution_complete": all(r.generated for r in results),
        "cases": [r.model_dump(mode="json") for r in results],
    }
    write_json(run / "reports/dataset.json", report)
    _check_implementation(run)
    _seal(run, plan, results)
    return report


def verify_dataset_promotion(run: Path, manifest: BundleManifest) -> None:
    """Recompute source-backed audits before qualified dataset publication."""
    plan = load_dataset(run)
    _check_implementation(run)
    if len(manifest.captures) != len(plan.cases) or {c.id for c in manifest.captures} != {
        c.id for c in plan.cases
    }:
        raise ValueError("Dataset qualified population differs from plan")
    for case in plan.cases:
        verify_capture_inputs(run, plan, case)
        folder = run / "private/attempts" / case.id
        native = folder / "private/native"
        scenario = json.loads((folder / "private/scenario.json").read_bytes())
        expectations = [
            EffectExpectation.model_validate(e)
            for e in json.loads((run / case.expectations).read_bytes())
        ]
        audit = audit_native(native, scenario, expectations)
        if not audit.passed or audit.model_dump(mode="json") != json.loads(
            (run / "reports/audits" / f"{case.id}.json").read_bytes()
        ):
            raise ValueError("Dataset native effect audit failed or changed")
        capture_hash = _capture_digest(native)
        capture = next(c for c in manifest.captures if c.id == case.id)
        if not capture.qualified or capture.source_sha256 != capture_hash:
            raise ValueError("Dataset capture hash or qualification mismatch")
    verify_dataset_public(run)


def verify_capture_inputs(run: Path, plan: DatasetPlan, case: DatasetCase) -> None:
    """Verify reusable generation bytes, verdicts, frozen scenario, seed and private truth."""
    from ..replay import verify_bundle

    folder = run / "private/attempts" / case.id
    verify_bundle(folder)
    backend = BackendIdentity.model_validate_json((folder / "sources/backend.json").read_bytes())
    options = GenerationOptions.model_validate_json(
        (folder / "sources/generation.json").read_bytes()
    )
    if backend != plan.backend or options != GenerationOptions(
        seed=case.seed, stage_timeout_seconds=plan.spec.stage_timeout_seconds
    ):
        raise ValueError("Dataset execution provenance differs from frozen plan")
    status = GenerationStatus.model_validate_json((folder / "reports/generation.json").read_bytes())
    if (
        status.status != "succeeded"
        or status.backend_passed is not True
        or [s.stage for s in status.stages] != ["validate", "generate", "quality"]
        or any(s.exit != 0 for s in status.stages)
    ):
        raise ValueError("Dataset capture lacks backend acceptance")
    from ..bundle import QualityReport

    if not QualityReport.model_validate_json(
        (folder / "reports/stages/quality.stdout").read_bytes()
    ).acceptance_passed:
        raise ValueError("Dataset backend quality rejected capture")
    expected = json.loads((run / case.scenario).read_bytes())
    document = ScenarioDocument.model_validate(expected)
    compiled, _ = compile_document(document, load_catalog(run / "sources/attack"))
    scenario = json.loads((folder / "private/scenario.json").read_bytes())
    if scenario != compiled:
        raise ValueError("Generated scenario differs from frozen dataset")
    native = folder / "private/native"
    selected_truth = GroundTruth.model_validate_json(
        (folder / "private/ground-truth.json").read_bytes()
    )
    if selected_truth != document.ground_truth:
        raise ValueError("Dataset private truth differs from frozen author intent")
    truth_path = native / "GROUND_TRUTH.json"
    overlay = annotate_native_truth(
        json.loads(truth_path.read_bytes()),
        selected_truth,
        authored_counts=authored_cardinality(scenario),
    )
    overlay.update(source_sha256=digest(truth_path), eligible=False)
    if overlay != json.loads((folder / "private/scenar-ground-truth.json").read_bytes()):
        raise ValueError("Dataset native truth annotation differs from frozen author intent")
