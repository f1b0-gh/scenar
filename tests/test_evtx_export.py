import json
import subprocess
from pathlib import Path

import pytest

from scenar.backend import inspect_backend
from scenar.bundle import Artifact, BundleManifest
from scenar.io import digest, files, write_json
from scenar.storage import export_public
from tests.test_backend import checkout


def source_bundle(tmp_path):
    root = tmp_path / "bundle"
    write_json(root / "private/truth.json", {"secret": "PRIVATE_SENTINEL"})
    windows = root / "public/capture/windows_event_security.xml"
    windows.parent.mkdir(parents=True)
    windows.write_text("<Events></Events>")
    for name in ("conn.json", "dns.json"):
        (windows.parent / name).write_bytes(b'{"id":"C1"}\n')
    seal(root)
    return root


def seal(root):
    manifest = BundleManifest(
        bundle_id="controlled",
        files=[
            Artifact(path=name, sha256=sha, size=(root / name).stat().st_size)
            for name, sha in files(root).items()
            if name != "manifest.json"
        ],
    )
    write_json(root / "manifest.json", manifest.model_dump(by_alias=True))


def encoder(tmp_path, monkeypatch, failure=False):
    root = checkout(tmp_path / "encoder")
    pin = inspect_backend(root)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert args[:6] == ["uv", "run", "--locked", "--project", str(root), "eforge"]
        assert args[6] == "export-evtx"
        assert kwargs["cwd"] == root
        Path(args[8]).write_bytes(b"ElfFile\x00" + b"\0" * 8192)
        if failure:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("scenar.evtx_export.run_encoder_command", run)
    return root, pin, calls


def test_evtx_export_external_pinned_encoder_and_private_receipt(tmp_path, monkeypatch):
    source = source_bundle(tmp_path)
    before = files(source)
    backend, pin, calls = encoder(tmp_path, monkeypatch)
    target = tmp_path / "public"
    receipt = tmp_path / "receipt.json"
    export_public(source, target, windows_format="evtx", backend=backend, pin=pin, receipt=receipt)
    assert len(calls) == 1
    assert set(files(target)) == {
        "capture/windows_event_security.evtx",
        "capture/conn.json",
        "capture/dns.json",
    }
    assert (target / "capture/conn.json").read_bytes() == (
        source / "public/capture/conn.json"
    ).read_bytes()
    assert (target / "capture/dns.json").read_bytes() == (
        source / "public/capture/dns.json"
    ).read_bytes()
    report = json.loads(receipt.read_bytes())
    assert report["encoder"]["source_sha256"] == pin.source_sha256
    conversion = report["conversions"][0]
    assert conversion["source"]["sha256"] == digest(
        source / "public/capture/windows_event_security.xml"
    )
    assert conversion["output"]["sha256"] == digest(target / "capture/windows_event_security.evtx")
    assert "PRIVATE_SENTINEL" not in receipt.read_text()
    assert files(source) == before


def test_encoder_failure_leaves_no_completed_export_or_receipt(tmp_path, monkeypatch):
    source = source_bundle(tmp_path)
    backend, pin, calls = encoder(tmp_path, monkeypatch, failure=True)
    target, receipt = tmp_path / "public", tmp_path / "receipt.json"
    with pytest.raises(subprocess.CalledProcessError):
        export_public(
            source, target, windows_format="evtx", backend=backend, pin=pin, receipt=receipt
        )
    assert calls
    assert not target.exists()
    assert not receipt.exists()
    assert not list(tmp_path.glob(".export-*"))


def test_corrupt_source_rejected_before_encoder(tmp_path, monkeypatch):
    source = source_bundle(tmp_path)
    backend, pin, calls = encoder(tmp_path, monkeypatch)
    (source / "public/capture/windows_event_security.xml").write_text("tampered")
    with pytest.raises(ValueError, match="checksum"):
        export_public(
            source,
            tmp_path / "public",
            windows_format="evtx",
            backend=backend,
            pin=pin,
            receipt=tmp_path / "receipt.json",
        )
    assert not calls


def test_receipt_must_be_outside_public_and_frozen_source(tmp_path):
    source = source_bundle(tmp_path)
    for receipt in (tmp_path / "public/receipt.json", source / "receipt.json"):
        with pytest.raises(ValueError, match="outside"):
            export_public(source, tmp_path / "public", windows_format="evtx", receipt=receipt)
    assert not (tmp_path / "public").exists()


def test_evtx_requires_explicit_pin_and_receipt(tmp_path):
    source = source_bundle(tmp_path)
    with pytest.raises(ValueError, match="pin.*receipt"):
        export_public(source, tmp_path / "public", windows_format="evtx")


def test_encoder_pin_mismatch_rejected_before_conversion(tmp_path, monkeypatch):
    source = source_bundle(tmp_path)
    backend, pin, calls = encoder(tmp_path, monkeypatch)
    (backend / "src/evidenceforge/__init__.py").write_text("# changed\n")
    with pytest.raises(ValueError, match="identity mismatch"):
        export_public(
            source,
            tmp_path / "public",
            windows_format="evtx",
            backend=backend,
            pin=pin,
            receipt=tmp_path / "receipt.json",
        )
    assert not calls
    assert not (tmp_path / "public").exists()


def test_output_collision_rejected_before_conversion(tmp_path, monkeypatch):
    source = source_bundle(tmp_path)
    (source / "public/capture/windows_event_security.evtx").write_bytes(b"existing")
    seal(source)
    backend, pin, calls = encoder(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="collision"):
        export_public(
            source,
            tmp_path / "public",
            windows_format="evtx",
            backend=backend,
            pin=pin,
            receipt=tmp_path / "receipt.json",
        )
    assert not calls


@pytest.mark.parametrize("failure", ["timeout", "signature"])
def test_invalid_encoder_result_rolls_back_export(tmp_path, monkeypatch, failure):
    source = source_bundle(tmp_path)
    backend, pin, _ = encoder(tmp_path, monkeypatch)

    def run(args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 1)
        Path(args[8]).write_text("<Events/>")

    monkeypatch.setattr("scenar.evtx_export.run_encoder_command", run)
    with pytest.raises((subprocess.TimeoutExpired, ValueError)):
        export_public(
            source,
            tmp_path / "public",
            windows_format="evtx",
            backend=backend,
            pin=pin,
            receipt=tmp_path / "receipt.json",
        )
    assert not (tmp_path / "public").exists()
    assert not (tmp_path / "receipt.json").exists()


def test_encoder_environment_is_independent(tmp_path, monkeypatch):
    source = source_bundle(tmp_path)
    backend, pin, _ = encoder(tmp_path, monkeypatch)
    monkeypatch.setenv("UV_PROJECT_ENVIRONMENT", "/must-not-reuse-scenar-env")

    def run(args, **kwargs):
        assert "UV_PROJECT_ENVIRONMENT" not in kwargs["env"]
        assert kwargs["timeout"] == 12
        Path(args[8]).write_bytes(b"ElfFile\x00")

    monkeypatch.setattr("scenar.evtx_export.run_encoder_command", run)
    export_public(
        source,
        tmp_path / "public",
        windows_format="evtx",
        backend=backend,
        pin=pin,
        receipt=tmp_path / "receipt.json",
        timeout=12,
    )


def test_destination_cannot_mutate_frozen_bundle(tmp_path):
    source = source_bundle(tmp_path)
    before = files(source)
    with pytest.raises(ValueError, match="outside"):
        export_public(source, source / "new-export")
    assert files(source) == before


@pytest.mark.parametrize("mutation", ["extra", "cache", "changed", "symlink"])
def test_encoder_cannot_mutate_public_inventory(tmp_path, monkeypatch, mutation):
    source = source_bundle(tmp_path)
    backend, pin, _ = encoder(tmp_path, monkeypatch)

    def run(args, **kwargs):
        output = Path(args[8])
        if mutation == "symlink":
            output.symlink_to(source / "private/truth.json")
        else:
            output.write_bytes(b"ElfFile\x00")
            name = {"extra": "truth.json", "cache": "private.pyc"}.get(mutation, "conn.json")
            (output.parent / name).write_text("private mutation")

    monkeypatch.setattr("scenar.evtx_export.run_encoder_command", run)
    with pytest.raises(ValueError, match="inventory|Symlink"):
        export_public(
            source,
            tmp_path / "public",
            windows_format="evtx",
            backend=backend,
            pin=pin,
            receipt=tmp_path / "receipt.json",
        )
    assert not (tmp_path / "public").exists()
    assert not (tmp_path / "receipt.json").exists()


def test_real_encoder_timeout_terminates_descendants(tmp_path):
    import os
    import sys
    import time

    from scenar.evtx_export import run_encoder_command

    marker = tmp_path / "surviving-child"
    child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).write_text('leak')"
    script = f"import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(30)"
    with pytest.raises(subprocess.TimeoutExpired):
        run_encoder_command(
            [sys.executable, "-c", script], cwd=tmp_path, timeout=0.2, env=os.environ.copy()
        )
    time.sleep(1.1)
    assert not marker.exists()


def test_manifest_replacement_during_verification_is_rejected(tmp_path, monkeypatch):
    from scenar.replay import verify_bundle

    source = source_bundle(tmp_path)

    def changed_manifest(root):
        result = verify_bundle(root)
        path = root / "manifest.json"
        path.write_bytes(path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr("scenar.storage.verify_bundle", changed_manifest)
    with pytest.raises(ValueError, match="manifest changed"):
        export_public(source, tmp_path / "public")
    assert not (tmp_path / "public").exists()


@pytest.mark.parametrize("existing", ["public", "receipt.json"])
def test_export_does_not_overwrite_existing_destination_or_receipt(tmp_path, monkeypatch, existing):
    source = source_bundle(tmp_path)
    backend, pin, calls = encoder(tmp_path, monkeypatch)
    path = tmp_path / existing
    path.write_text("retained")
    with pytest.raises(FileExistsError):
        export_public(
            source,
            tmp_path / "public",
            windows_format="evtx",
            backend=backend,
            pin=pin,
            receipt=tmp_path / "receipt.json",
        )
    assert not calls
    assert path.read_text() == "retained"


def test_nonregular_encoder_output_is_rejected_before_open(tmp_path, monkeypatch):
    import os

    from scenar.evtx_export import encode_windows

    source, output = tmp_path / "input.xml", tmp_path / "output.evtx"
    source.write_text("<Events/>")

    def run(args, **kwargs):
        os.mkfifo(output)

    def forbidden_open(*args, **kwargs):
        raise AssertionError("Opening a FIFO would block outside the encoder timeout")

    monkeypatch.setattr("scenar.evtx_export.run_encoder_command", run)
    monkeypatch.setattr(Path, "open", forbidden_open)
    with pytest.raises(ValueError, match="regular"):
        encode_windows(source, output, tmp_path, 1)
