"""Verify frozen bytes and regrade into a new run; never regenerate history."""

import hashlib
import json
import shutil
import tarfile
from pathlib import Path

import yaml

from .attack import load_catalog
from .bundle import BundleManifest, CaptureResult, RunProtocol
from .io import digest, files, safe_path, write_json
from .runner import (
    freeze_sources,
    load_protocol,
    qualify_capture,
    save_protocol,
    seal_bundle,
    summarize_run,
)
from .scenario import AttackSettings, resolve_attack
from .truth import GroundTruth


def verify_bundle(root: Path) -> BundleManifest:
    manifest = BundleManifest.model_validate_json((root / "manifest.json").read_bytes())
    expected = {f.path for f in manifest.files}
    actual = set(files(root)) - {"manifest.json"}
    if expected != actual:
        raise ValueError("Bundle file inventory differs from manifest")
    for artifact in manifest.files:
        path = safe_path(root, artifact.path)
        if path.stat().st_size != artifact.size or digest(path) != artifact.sha256:
            raise ValueError(f"Bundle checksum mismatch: {artifact.path}")
    return manifest


def verify_legacy(root: Path) -> dict:
    freeze = json.loads((root / "freeze.json").read_bytes())
    for name, key in (
        ("protocol.json", "protocol_sha256"),
        ("source.tar.gz", "source_archive_sha256"),
    ):
        if digest(root / name) != freeze[key]:
            raise ValueError(f"Legacy checksum mismatch: {name}")
    protocol = json.loads((root / "protocol.json").read_bytes())
    for case in protocol["cases"]:
        if digest(safe_path(root, case["scenario"])) != case["scenario_sha256"]:
            raise ValueError("Legacy scenario checksum mismatch")
    raw = {
        f"{case['id']}/bundle/{name}": sha
        for case in protocol["cases"]
        for name, sha in files(safe_path(root, f"attempts/{case['id']}/bundle")).items()
    }
    retained = {}
    with tarfile.open(root / "native-captures.tar.gz") as archive:
        for member in archive:
            if member.issym() or member.islnk():
                raise ValueError("Unsafe archived link")
            if member.isfile():
                safe_path(root, member.name)
                if member.name in retained:
                    raise ValueError("Duplicate archived capture path")
                retained[member.name] = hashlib.file_digest(
                    archive.extractfile(member), "sha256"
                ).hexdigest()
    if raw != retained:
        raise ValueError("Native capture checksum mismatch with completed archive")
    return protocol


def replay_run(
    source: Path,
    destination: Path,
    *,
    annotate_attack: bool = False,
    catalog_path: Path | None = None,
    ground_truth: GroundTruth | None = None,
) -> BundleManifest:
    if destination.exists():
        raise FileExistsError("Replay destination must be new")
    legacy = not (source / "manifest.json").exists()
    if legacy:
        original = verify_legacy(source)
        summary_path = source / "summary.json"
        attempts_root = source / "attempts"
    else:
        verify_bundle(source)
        original = load_protocol(source).model_dump(mode="json")
        summary_path = source / "reports/summary.json"
        attempts_root = source / "private/attempts"
    summary = json.loads(summary_path.read_bytes())
    attempts = summary["attempts"]
    if len(attempts) != len(original["cases"]) or {a["id"] for a in attempts} != {
        c["id"] for c in original["cases"]
    }:
        raise ValueError("Original attempt population is incomplete or duplicated")
    # Validate path-bearing identities before copying or creating any destination.
    protocol = RunProtocol(
        backend=None,
        cases=original["cases"],
        start=original["start"],
        as_of=original["as_of"],
        budgets=original["budgets"],
        policies=original["policies"],
        contexts=original["contexts"],
        stage_timeout_seconds=original["stage_timeout_seconds"],
        sources={},
        origin="legacy-replay" if legacy else "replay",
        catalog_sha256=original.get("catalog_sha256"),
    )
    catalog = None
    if annotate_attack or catalog_path is not None:
        catalog = load_catalog(catalog_path)
        protocol.catalog_sha256 = catalog.sha256
        for case in protocol.cases:
            scenario = yaml.safe_load(safe_path(source, case.scenario).read_text())
            case.attack = resolve_attack(scenario, AttackSettings(domain=catalog.domain), catalog)
    if ground_truth is not None:
        for case in protocol.cases:
            members = {m.authored_record_id: m.episode_ids for m in case.private.members}
            ground_truth.bind(members, {})
            case.ground_truth = ground_truth
    for a in attempts:
        CaptureResult.model_validate(a)
    destination.mkdir(parents=True)
    protocol.sources = freeze_sources(destination)
    if catalog is not None:
        write_json(destination / "sources/attack/catalog.json", catalog.model_dump(mode="json"))
        write_json(
            destination / "sources/attack/pin.json",
            {"catalog_sha256": catalog.sha256, "source_sha256": catalog.source_sha256},
        )
    elif protocol.catalog_sha256:
        shutil.copytree(safe_path(source, "sources/attack"), destination / "sources/attack")
    for case in protocol.cases:
        target = safe_path(destination, case.scenario)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_path(source, case.scenario), target)
    save_protocol(destination, protocol)
    restricted = destination / "sources/original"
    restricted.mkdir()
    for name in (
        ("protocol.json", "freeze.json", "source.tar.gz", "native-captures.tar.gz")
        if legacy
        else ("manifest.json", "private/protocol.json", "sources/freeze.json")
    ):
        target = safe_path(restricted, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_path(source, name), target)
    write_json(
        destination / "sources/replay-provenance.json",
        {
            "regenerated": False,
            "original_summary_sha256": digest(summary_path),
            "original_manifest_sha256": None if legacy else digest(source / "manifest.json"),
            "original_protocol_sha256": digest(
                source / ("protocol.json" if legacy else "private/protocol.json")
            ),
            "mode": "regrade-with-current-harness",
            "attack_reannotated": catalog is not None,
            "intent_readjudicated": ground_truth is not None,
        },
    )
    by_id = {a["id"]: a for a in attempts}
    for case in protocol.cases:
        old = safe_path(attempts_root, case.id)
        folder = destination / "private/attempts" / case.id
        folder.mkdir(parents=True)
        attempt = CaptureResult(id=case.id, stages=by_id[case.id]["stages"])
        if (old / "bundle").exists():
            shutil.copytree(old / "bundle", folder / "bundle")
        for path in old.glob("*.stdout"):
            shutil.copyfile(path, folder / path.name)
        for path in old.glob("*.stderr"):
            shutil.copyfile(path, folder / path.name)
        if len(attempt.stages) == 3 and all(s.exit == 0 for s in attempt.stages):
            try:
                q = qualify_capture(destination, case.id)
                attempt.eligible, attempt.native_eligible = q.eligible, q.native_passed
            except (ValueError, OSError, KeyError) as exc:
                attempt.error = f"{type(exc).__name__}: {exc}"
        else:
            attempt.error = "Original generation stages failed; no regeneration attempted"
        write_json(folder / "attempt.json", attempt.model_dump())
    summarize_run(destination)
    return seal_bundle(destination)
