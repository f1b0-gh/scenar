import json

import pytest

from scenar.io import write_json
from scenar.storage import export_public, publish_bundle, pull_bundle


def bundle(tmp_path, qualified=True):
    from scenar.backend import inspect_backend
    from scenar.runner import prepare_run, seal_bundle
    from tests.test_backend import checkout

    backend = checkout(tmp_path / "backend")
    root = tmp_path / "bundle"
    protocol = prepare_run(
        "investigation-episodes",
        root,
        backend=backend,
        pin=inspect_backend(backend),
        families=("benign_only",),
    )
    write_json(root / "public/feed.json", {"candidates": []})
    write_json(root / "private/truth.json", {"secret": True})
    for case in protocol.cases:
        folder = root / "private/attempts" / case.id
        write_json(folder / "bundle/data.json", {"record": case.seed})
        write_json(
            folder / "attempt.json",
            {
                "id": case.id,
                "eligible": qualified,
                "native_eligible": qualified,
                "stages": [
                    {"stage": stage, "args": [], "exit": 0, "elapsed_seconds": 0}
                    for stage in ("validate", "generate", "quality")
                ],
            },
        )
        write_json(
            folder / "qualification.json", {"native_passed": qualified, "backend_passed": qualified}
        )
        write_json(folder / "quality.stdout", {"acceptance_passed": qualified})
    m = seal_bundle(root)
    m.bundle_id = "build1"
    write_json(root / "manifest.json", m.model_dump(by_alias=True))
    return root


def test_local_publish_pull_and_public_only_export(tmp_path):
    root = bundle(tmp_path)
    store = tmp_path / "store"
    publish_bundle(root, str(store))
    pulled = pull_bundle(str(store), tmp_path / "pulled")
    assert pulled.bundle_id == "build1"
    assert (tmp_path / "pulled/private/truth.json").exists()
    export_public(root, tmp_path / "inputs")
    assert {
        p.relative_to(tmp_path / "inputs").as_posix()
        for p in (tmp_path / "inputs").rglob("*")
        if p.is_file()
    } == {"feed.json"}
    with pytest.raises(FileExistsError):
        publish_bundle(root, str(store))


def test_diagnostic_publish_never_promotes_qualified_pointer(tmp_path):
    root = bundle(tmp_path, False)
    store = tmp_path / "store"
    with pytest.raises(ValueError, match="qualified"):
        publish_bundle(root, str(store))
    publish_bundle(root, str(store), diagnostic=True)
    assert not (store / "latest.json").exists()


def test_pull_rejects_traversal_and_corruption(tmp_path):
    root = bundle(tmp_path)
    m = json.loads((root / "manifest.json").read_text())
    m["files"][0]["path"] = "../escape"
    write_json(root / "manifest.json", m)
    with pytest.raises(ValueError):
        pull_bundle(str(root), tmp_path / "pulled")
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "pulled").exists()


def test_manifest_flag_cannot_promote_rejected_capture(tmp_path):
    root = bundle(tmp_path, False)
    manifest = json.loads((root / "manifest.json").read_bytes())
    for capture in manifest["captures"]:
        capture["qualified"] = True
    write_json(root / "manifest.json", manifest)
    with pytest.raises(ValueError):
        publish_bundle(root, str(tmp_path / "store"))
    assert not (tmp_path / "store/latest.json").exists()


def test_list_ignores_nested_provenance_manifests(tmp_path):
    from scenar.storage import list_bundles

    root = bundle(tmp_path)
    store = tmp_path / "store"
    published = publish_bundle(root, str(store))
    write_json(store / "builds/build1/sources/original/manifest.json", {})
    assert list_bundles(str(store)) == [published]


def test_legacy_manifest_is_pulled_byte_for_byte_without_qualification(tmp_path):
    from scenar.io import digest

    original = tmp_path / "old"
    original.mkdir()
    (original / "events.json").write_text('{"events":[]}\n')
    data = {
        "schema": "lookout-scenar/manifest/v1",
        "build_id": "legacy-1",
        "files": [
            {
                "path": "events.json",
                "sha256": digest(original / "events.json"),
                "size": (original / "events.json").stat().st_size,
            }
        ],
    }
    write_json(original / "manifest.json", data)
    target = tmp_path / "download"
    result = pull_bundle(str(original), target)
    assert not result.qualified
    assert (target / "manifest.json").read_bytes() == (original / "manifest.json").read_bytes()


def test_bucket_environment_migration_preserves_precedence(monkeypatch):
    from scenar.storage import default_store

    monkeypatch.delenv("SCENAR_BUCKET", raising=False)
    monkeypatch.setenv("LOOKOUT_BUCKET", "legacy")
    with pytest.warns(UserWarning, match="deprecated"):
        assert default_store() == "s3://legacy"
    monkeypatch.setenv("SCENAR_BUCKET", "scenar")
    assert default_store() == "s3://scenar"
