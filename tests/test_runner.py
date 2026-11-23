import pytest

from scenar.backend import inspect_backend
from scenar.runner import load_protocol, prepare_run, run_all
from tests.test_backend import checkout


def test_prepare_freezes_inputs_and_refuses_overwrite(tmp_path):
    root = checkout(tmp_path / "backend")
    run = tmp_path / "run"
    protocol = prepare_run(
        "investigation-episodes",
        run,
        backend=root,
        pin=inspect_backend(root),
        families=("benign_only",),
    )
    assert len(protocol.cases) == 2
    assert load_protocol(run) == protocol
    with pytest.raises(FileExistsError):
        prepare_run("investigation-episodes", run, backend=root, pin=inspect_backend(root))
    scenario = run / protocol.cases[0].scenario
    scenario.write_text(scenario.read_text() + " ")
    with pytest.raises(ValueError, match="changed"):
        load_protocol(run)


def test_validation_failure_conserves_all_planned_slots(tmp_path):
    root = checkout(tmp_path / "backend")
    run = tmp_path / "run"
    prepare_run(
        "investigation-episodes",
        run,
        backend=root,
        pin=inspect_backend(root),
        families=("benign_only",),
    )

    # Real subprocess produces an explicit failed validation without needing a full backend.
    def command(checkout, *args):
        import sys

        return [sys.executable, "-c", "raise SystemExit(7)"]

    result = run_all(run, backend=root, command_factory=command)
    assert result["planned_captures"] == 2
    assert len(result["attempts"]) == 2
    assert result["qualified_captures"] == 0
    assert not result["execution_complete"]
    assert all(a["stages"][0]["exit"] == 7 for a in result["attempts"])
    with pytest.raises(ValueError, match="started"):
        run_all(run, backend=root, command_factory=command)


def test_timeout_stops_child_writes(tmp_path):
    import sys
    import time

    from scenar.runner import execute

    marker = tmp_path / "late-write"
    child = f"import time; from pathlib import Path; time.sleep(2); Path({str(marker)!r}).write_text('bad')"
    parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(10)"
    stage = execute([sys.executable, "-c", parent], tmp_path, "timeout", 1, tmp_path)
    assert stage.exit == 124
    time.sleep(1.5)
    assert not marker.exists()


def test_interrupt_stops_backend_descendant_writes(tmp_path):
    import os
    import signal
    import subprocess
    import sys
    import time

    import pytest

    if os.name != "posix":
        pytest.skip("SIGINT/process groups are POSIX-specific")
    marker = tmp_path / "child-writes"
    child_pid = tmp_path / "child-pid"
    child = (
        "import os,time; from pathlib import Path; "
        f"Path({str(child_pid)!r}).write_text(str(os.getpid())); "
        f"p=Path({str(marker)!r}); "
        "\nwhile True:\n p.write_text(str(time.time_ns())); time.sleep(0.02)\n"
    )
    parent = f'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",{child!r}]); time.sleep(30)'
    driver = (
        "from pathlib import Path; import sys; from scenar.runner import execute; "
        f'execute([sys.executable,"-c",{parent!r}], Path({str(tmp_path)!r}), "interrupt", 60, Path({str(tmp_path)!r}))'
    )
    process = subprocess.Popen(
        [sys.executable, "-c", driver], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), "Backend child did not start"
        process.send_signal(signal.SIGINT)
        process.wait(timeout=5)
        before = marker.read_bytes()
        time.sleep(0.15)
        assert marker.read_bytes() == before, "Backend child kept writing after Scenar interruption"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if child_pid.exists():
            try:
                os.kill(int(child_pid.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
