"""Frozen experiments with independent generation, qualification, and scoring."""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
import uuid
from importlib.resources import files as resources
from pathlib import Path

import yaml

from .attack import load_catalog
from .backend import BackendIdentity, active_pin, backend_command, backend_path, check_backend
from .background import BackgroundActivity, apply_background
from .bundle import (
    Artifact,
    BundleManifest,
    Capture,
    CaptureResult,
    Evaluation,
    Qualification,
    QualityReport,
    RunProtocol,
    Stage,
    View,
)
from .evaluation import episodes, pack
from .io import canonical, digest, files, safe_path, write_json
from .scenario import AttackSettings, resolve_attack
from .truth import GroundTruth

PACKAGE = Path(__file__).parent


def freeze_sources(run: Path) -> dict[str, str]:
    source = run / "sources/scenar"
    shutil.copytree(PACKAGE, source, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return files(source)


def prepare_run(
    pack_name: str | Path,
    destination: Path,
    *,
    backend: Path | None = None,
    families: tuple[str, ...] = pack.FAMILIES,
    pin: BackendIdentity | None = None,
    catalog_path: Path | None = None,
    ground_truth: GroundTruth | None = None,
    background: BackgroundActivity | None = None,
) -> RunProtocol:
    if str(pack_name) not in ("investigation-episodes", "packs/investigation-episodes"):
        raise ValueError("Supported generation pack: investigation-episodes")
    if (
        not families
        or len(set(families)) != len(families)
        or not set(families) <= set(pack.FAMILIES)
    ):
        raise ValueError("Invalid family selection")
    pin = pin or active_pin()
    check_backend(backend_path(backend), pin)
    source = resources("scenar") / "resources/investigation-episodes"
    base = yaml.safe_load((source / "attack-cmd.yaml").read_text())
    template = json.loads((source / "contracts.json").read_text())["cases"][0]
    catalog = load_catalog(catalog_path)
    ground_truth = ground_truth or GroundTruth()
    recipes = []
    for family in families:
        recipe = pack.make_case(base, family, template)
        members = {m["authored_record_id"]: m["episode_ids"] for m in recipe["private"]["members"]}
        ground_truth.bind(members, {})
        if background:
            recipe["scenario_value"] = apply_background(recipe["scenario_value"], background)
        attack = resolve_attack(
            recipe["scenario_value"], AttackSettings(domain=catalog.domain), catalog
        )
        recipes.append((family, recipe, attack))
    destination.mkdir(parents=True, exist_ok=False)
    write_json(destination / "sources/attack/catalog.json", catalog.model_dump(mode="json"))
    write_json(
        destination / "sources/attack/pin.json",
        {"catalog_sha256": catalog.sha256, "source_sha256": catalog.source_sha256},
    )
    cases = []
    for family, case, attack in recipes:
        path = destination / "private/scenarios" / (family + ".json")
        write_json(path, case.pop("scenario_value"))
        for seed in (9501, 9502):
            cases.append(
                {
                    **case,
                    "id": f"{family}-{seed}",
                    "family": family,
                    "seed": seed,
                    "scenario": path.relative_to(destination).as_posix(),
                    "scenario_sha256": digest(path),
                    "attack": attack,
                    "ground_truth": ground_truth,
                    "background": background,
                }
            )
    protocol = RunProtocol(
        backend=pin,
        cases=cases,
        start="2024-05-27T12:00:00Z",
        as_of="2024-05-27T12:15:00Z",
        sources=freeze_sources(destination),
        catalog_sha256=catalog.sha256,
    )
    save_protocol(destination, protocol)
    return protocol


def save_protocol(run: Path, protocol: RunProtocol) -> None:
    write_json(run / "private/protocol.json", protocol.model_dump(mode="json", by_alias=True))
    write_json(
        run / "sources/freeze.json",
        {"protocol_sha256": digest(run / "private/protocol.json"), "sources": protocol.sources},
    )


def load_protocol(run: Path) -> RunProtocol:
    freeze = json.loads((run / "sources/freeze.json").read_bytes())
    path = run / "private/protocol.json"
    if digest(path) != freeze["protocol_sha256"]:
        raise ValueError("Frozen protocol changed")
    protocol = RunProtocol.model_validate_json(path.read_bytes())
    if protocol.catalog_sha256:
        catalog = load_catalog(run / "sources/attack")
        if catalog.sha256 != protocol.catalog_sha256 or any(
            c.attack is None or c.attack.catalog_sha256 != catalog.sha256 for c in protocol.cases
        ):
            raise ValueError("Frozen ATT&CK catalogue differs from protocol")
    if protocol.sources != freeze["sources"] or files(run / "sources/scenar") != protocol.sources:
        raise ValueError("Frozen evaluator sources changed")
    for case in protocol.cases:
        if digest(safe_path(run, case.scenario)) != case.scenario_sha256:
            raise ValueError("Frozen scenario changed")
    return protocol


def execute(args: list[str], folder: Path, stage: str, timeout: int, cwd: Path) -> Stage:
    begin = time.perf_counter()
    with (
        (folder / f"{stage}.stdout").open("wb") as out,
        (folder / f"{stage}.stderr").open("wb") as err,
    ):
        with subprocess.Popen(
            args, cwd=cwd, stdout=out, stderr=err, start_new_session=os.name == "posix"
        ) as process:
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _stop_backend(process)
                code = 124
            except BaseException:
                # The backend has its own session: Ctrl-C to Scenar does not reach it.
                # Reap it before generation seals diagnostic artifacts or resume snapshots them.
                _stop_backend(process)
                raise
    return Stage(stage=stage, args=args, exit=code, elapsed_seconds=time.perf_counter() - begin)


def _stop_backend(process: subprocess.Popen) -> None:
    """Stop the backend process tree before exposing or sealing its output."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
        process.kill()
    process.wait()


def qualify_capture(run: Path, case_id: str) -> Qualification:
    protocol = load_protocol(run)
    case = next((c for c in protocol.cases if c.id == case_id), None)
    if case is None:
        raise ValueError("Unknown planned capture")
    folder = safe_path(run, f"private/attempts/{case_id}")
    quality = QualityReport.model_validate_json((folder / "quality.stdout").read_bytes())
    # The preserved evaluator checks all native linkage before any policy runs.
    rows = episodes.evaluate_capture(
        folder, case.model_dump(mode="json"), protocol.model_dump(mode="json")
    )
    status = json.loads((folder / "eligibility.json").read_bytes())
    qualification = Qualification(
        native_passed=status.get("native_eligible", False),
        backend_passed=quality.acceptance_passed,
        reasons=status["errors"],
    )
    write_json(folder / "comparisons.json", rows)
    write_json(folder / "qualification.json", qualification.model_dump())
    from .analysis_reports import capture_reports

    capture_reports(run, case, qualification)
    # Opaque public filename; only the allowlisted candidate feed crosses the boundary.
    capture_id = hashlib.sha256(canonical(files(folder / "bundle"))).hexdigest()
    if (folder / "candidate-feed.json").exists():
        feed = json.loads((folder / "candidate-feed.json").read_bytes())
        write_json(run / "public" / f"{capture_id}.json", feed)
    for source in folder.glob("broker-snapshot-*.json.gz"):
        target = run / "broker" / capture_id / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return qualification


def run_capture(
    run: Path, case_id: str, *, backend: Path | None = None, command_factory=backend_command
) -> CaptureResult:
    protocol = load_protocol(run)
    root = backend_path(backend)
    if protocol.backend is None:
        raise ValueError("Replay protocol cannot generate new captures")
    check_backend(root, protocol.backend)
    case = next((c for c in protocol.cases if c.id == case_id), None)
    if case is None:
        raise ValueError("Unknown planned capture")
    folder = safe_path(run, f"private/attempts/{case_id}")
    folder.mkdir(parents=True, exist_ok=False)
    attempt = CaptureResult(id=case_id)
    try:
        for name, args in (
            ("validate", ["validate", str((run / case.scenario).resolve())]),
            (
                "generate",
                [
                    "generate",
                    str((run / case.scenario).resolve()),
                    "--output",
                    str((folder / "bundle").resolve()),
                    "--seed",
                    str(case.seed),
                ],
            ),
            ("quality", ["eval", str((folder / "bundle").resolve()), "--format", "json"]),
        ):
            stage = execute(
                command_factory(root, *args), folder, name, protocol.stage_timeout_seconds, root
            )
            attempt.stages.append(stage)
            write_json(folder / "attempt.json", attempt.model_dump())
            if stage.exit:
                attempt.error = f"{name} failed with exit {stage.exit}"
                break
        if len(attempt.stages) == 3 and all(s.exit == 0 for s in attempt.stages):
            q = qualify_capture(run, case_id)
            attempt.eligible, attempt.native_eligible = q.eligible, q.native_passed
    except (ValueError, OSError, KeyError) as exc:
        attempt.error = f"{type(exc).__name__}: {exc}"
    write_json(folder / "attempt.json", attempt.model_dump())
    return attempt


def seal_bundle(run: Path) -> BundleManifest:
    protocol = load_protocol(run)
    captures = []
    views, evaluations = [], []
    evaluator_hash = hashlib.sha256(canonical(protocol.sources)).hexdigest()
    for case in protocol.cases:
        folder = run / "private/attempts" / case.id
        status = CaptureResult.model_validate_json((folder / "attempt.json").read_bytes())
        captures.append(
            Capture(
                id=case.id,
                family=case.family,
                qualified=status.eligible,
                source_sha256=hashlib.sha256(canonical(files(folder / "bundle"))).hexdigest(),
            )
        )
        comparison_file = folder / "comparisons.json"
        if comparison_file.exists():
            rows = json.loads(comparison_file.read_bytes())
            for context in sorted({row["context"] for row in rows}):
                view_id = hashlib.sha256(
                    canonical([captures[-1].source_sha256, context])
                ).hexdigest()
                # Capture IDs remain distinct planned attempts even if identical bytes occur.
                view_id = hashlib.sha256(canonical([case.id, view_id])).hexdigest()
                views.append(View(id=view_id, capture_id=case.id, context=context))
                for row in rows:
                    if row["context"] == context:
                        evaluations.append(
                            Evaluation(
                                id=hashlib.sha256(
                                    canonical(
                                        [view_id, row["policy"], row["budget"], evaluator_hash]
                                    )
                                ).hexdigest(),
                                view_id=view_id,
                                policy=row["policy"],
                                budget=row["budget"],
                                evaluator_sha256=evaluator_hash,
                            )
                        )
    artifacts = [
        Artifact(path=name, sha256=sha, size=(run / name).stat().st_size)
        for name, sha in files(run).items()
        if name != "manifest.json"
    ]
    provenance = run / "sources/replay-provenance.json"
    parent = digest(provenance) if provenance.exists() else None
    manifest = BundleManifest(
        bundle_id=uuid.uuid4().hex,
        captures=captures,
        views=views,
        evaluations=evaluations,
        files=artifacts,
        provenance="transformed" if parent else "synthetic",
        parent_sha256=parent,
    )
    write_json(run / "manifest.json", manifest.model_dump(mode="json", by_alias=True))
    return manifest


def summarize_run(run: Path) -> dict:
    protocol = load_protocol(run)
    attempts, results = [], []
    for case in protocol.cases:
        folder = run / "private/attempts" / case.id
        attempts.append(
            CaptureResult.model_validate_json((folder / "attempt.json").read_bytes()).model_dump()
        )
        if (folder / "comparisons.json").exists():
            results.extend(json.loads((folder / "comparisons.json").read_bytes()))
    summary = episodes.summarize(protocol.model_dump(mode="json"), attempts, results)
    write_json(run / "reports/summary.json", summary)
    return summary


def run_all(run: Path, *, backend: Path | None = None, command_factory=backend_command) -> dict:
    protocol = load_protocol(run)
    if (run / "private/attempts").exists():
        raise ValueError("Run already started; use a fresh directory or replay")
    if files(PACKAGE) != protocol.sources:
        raise ValueError("Evaluator source changed since preparation")
    for case in protocol.cases:
        run_capture(run, case.id, backend=backend, command_factory=command_factory)
    if files(PACKAGE) != protocol.sources:
        raise ValueError("Evaluator source changed during execution; attempts retained unsealed")
    summary = summarize_run(run)
    seal_bundle(run)
    return summary
