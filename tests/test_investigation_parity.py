import json
import os
from pathlib import Path

import pytest

from scenar.replay import replay_run


def test_frozen_capture_decisions_and_metrics_match(tmp_path):
    archive = os.environ.get("SCENAR_PARITY_ARCHIVE")
    if not archive:
        pytest.skip("Set SCENAR_PARITY_ARCHIVE to the preserved investigation-episodes run")
    source = Path(archive)
    dest = tmp_path / "replay"
    replay_run(source, dest)
    old = json.loads((source / "summary.json").read_text())
    new = json.loads((dest / "reports/summary.json").read_text())
    assert new["qualified_captures"] == old["qualified_captures"]
    assert new["planned_captures"] == old["planned_captures"]
    assert new["matrix_complete"] == old["matrix_complete"]
    assert len(new["results"]) == len(old["results"])
    for before, after in zip(old["results"], new["results"], strict=True):
        for key in ("case", "context", "policy", "budget", "diagnostic_only", "metrics"):
            assert after[key] == before[key], (key, before["case"])
        a = json.loads((source / "attempts" / before["case"] / before["result"]).read_text())
        b = json.loads((dest / "private/attempts" / after["case"] / after["result"]).read_text())
        assert a == b
