import json
import shutil
from pathlib import Path

import pytest

from scenar.authoring import build

pytestmark = pytest.mark.skipif(
    not shutil.which("nickel"), reason="Nickel optional frontend not installed"
)
ROOT = Path(__file__).parents[1]


def test_nickel_retains_benign_technique_and_declared_tactics(tmp_path):
    build(ROOT / "scenarios/branch-office", tmp_path / "built")
    mappings = json.loads((tmp_path / "built/private/attack.json").read_bytes())["mappings"]
    assert any(
        m["record_id"].startswith("rh-vpn-typo#") and m["technique"] == "T1078" for m in mappings
    )
    assert (
        next(m for m in mappings if m["record_id"] == "stage_archive#0")["tactic"] == "collection"
    )


def test_nickel_invalid_procedure_tactic_is_not_dropped_before_validation(tmp_path):
    source = tmp_path / "invalid.ncl"
    source.write_text(
        "let s = import "
        + json.dumps(str(ROOT / "scenarios/branch-office/main.ncl"))
        + ' in s & { steps | force = std.array.map (fun st => if st.id == "recon" then st & { procedure.technique.tactic | force = "not-a-tactic" } else st) s.steps }'
    )
    with pytest.raises(ValueError, match="tactic"):
        build(source, tmp_path / "out")
