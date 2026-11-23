import json

import pytest

from scenar.backend import inspect_backend
from scenar.replay import replay_run
from scenar.runner import prepare_run, run_all
from tests.test_backend import checkout


def failed_run(tmp_path):
    import sys

    root = checkout(tmp_path / "backend")
    source = tmp_path / "original"
    prepare_run(
        "investigation-episodes",
        source,
        backend=root,
        pin=inspect_backend(root),
        families=("benign_only",),
    )
    run_all(
        source,
        backend=root,
        command_factory=lambda root, *args: [sys.executable, "-c", "raise SystemExit(7)"],
    )
    return source


def test_replay_preserves_failed_slots_without_generation(tmp_path):
    source = failed_run(tmp_path)
    dest = tmp_path / "replay"
    result = replay_run(source, dest)
    assert len(result.captures) == 2
    assert not result.qualified
    summary = json.loads((dest / "reports/summary.json").read_text())
    assert len(summary["attempts"]) == 2
    assert all(a["stages"][0]["exit"] == 7 for a in summary["attempts"])


def test_replay_rejects_corruption_before_creating_destination(tmp_path):
    source = failed_run(tmp_path)
    (source / "reports/summary.json").write_text("{}")
    with pytest.raises(ValueError, match="checksum"):
        replay_run(source, tmp_path / "replay")
    assert not (tmp_path / "replay").exists()
