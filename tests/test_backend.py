from pathlib import Path

import pytest

from scenar.backend import check_backend, inspect_backend


def checkout(tmp_path: Path) -> Path:
    (tmp_path / "src/evidenceforge/config").mkdir(parents=True)
    (tmp_path / "src/evidenceforge/__init__.py").write_text('__version__ = "2.1.2"\n')
    (tmp_path / "src/evidenceforge/config/generation_behavior.yaml").write_text(
        "current_revision: 162\n"
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nname="evidence-forge"\nversion="2.1.2"\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    return tmp_path


def test_pin_rejects_changed_source_with_same_package_version(tmp_path):
    root = checkout(tmp_path)
    pin = inspect_backend(root)
    check_backend(root, pin)
    (root / "src/evidenceforge/__init__.py").write_text(
        '__version__ = "2.1.2"\n# changed behavior\n'
    )
    with pytest.raises(ValueError, match="identity"):
        check_backend(root, pin)


def test_snapshot_is_not_misrepresented_as_verified_upstream(tmp_path):
    identity = inspect_backend(checkout(tmp_path))
    assert identity.revision is None
    assert identity.upstream_verified is False
    assert identity.behavior_revision == 162
    assert len(identity.source_sha256) == 64


def test_missing_lock_is_not_an_unknown_success(tmp_path):
    root = checkout(tmp_path)
    (root / "uv.lock").unlink()
    with pytest.raises(ValueError, match="uv.lock"):
        inspect_backend(root)


def test_default_prepare_rejects_unpinned_backend(tmp_path):
    from scenar.runner import prepare_run

    root = checkout(tmp_path / "backend")
    with pytest.raises(ValueError, match="identity mismatch"):
        prepare_run("investigation-episodes", tmp_path / "run", backend=root)
    assert not (tmp_path / "run").exists()


def test_packaged_active_pin_matches_reviewable_toolchain_pin():
    from scenar.backend import active_pin, read_pin

    assert active_pin() == read_pin(Path(__file__).parents[1] / "toolchains/evidenceforge.json")
