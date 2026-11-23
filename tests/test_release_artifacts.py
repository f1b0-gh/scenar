"""Release checks inspect archives without extracting untrusted paths."""

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest


def checker():
    spec = importlib.util.spec_from_file_location(
        "release_check", Path(__file__).parents[1] / "tools/check_release.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wheel(
    tmp_path,
    extra=None,
    summary="Scenar builds reproducible synthetic security datasets",
    license_headers="",
):
    path = tmp_path / "scenar-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("scenar/__init__.py", '__version__ = "0.1.0"\n')
        archive.writestr("scenar/cli.py", "")
        archive.writestr("scenar/EVIDENCEFORGE-LICENSE.txt", "retained license")
        archive.writestr("scenar/resources/attack/LICENSE.txt", "retained license")
        archive.writestr("scenar/resources/attack/catalog.json", "{}")
        archive.writestr("scenar/resources/evidenceforge.json", "{}")
        archive.writestr(
            "scenar-0.1.0.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: scenar\nVersion: 0.1.0\nSummary: {summary}\n{license_headers}",
        )
        archive.writestr(
            "scenar-0.1.0.dist-info/entry_points.txt",
            "[console_scripts]\nscenar = scenar.cli:main\n",
        )
        for name, value in (extra or {}).items():
            archive.writestr(name, value)
    return path


def test_clean_wheel_retains_resources_and_attribution(tmp_path):
    report = checker().check_archive(wheel(tmp_path))
    assert report["kind"] == "wheel"
    assert report["files"] == 8


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".local/documentation/archive.md",
        "scenar/.local/notes.md",
        "scenar/.aws/credentials",
        "runs/private/truth.json",
        "bindings/scenar-native/vendor/case-dossier/src/lib.rs",
        "scenar/__pycache__/x.pyc",
        "../outside",
        "/absolute",
    ],
)
def test_release_rejects_local_or_unsafe_archive_members(tmp_path, name):
    with pytest.raises(ValueError):
        checker().check_archive(wheel(tmp_path, {name: "must not ship"}))


def test_release_rejects_embedded_private_key_without_echoing_it(tmp_path):
    secret = "-----BEGIN PRIVATE KEY-----\nSENTINEL-SECRET\n-----END PRIVATE KEY-----"
    with pytest.raises(ValueError) as error:
        checker().check_archive(wheel(tmp_path, {"scenar/key.txt": secret}))
    assert "SENTINEL-SECRET" not in str(error.value)


def test_release_detects_stale_description(tmp_path):
    with pytest.raises(ValueError, match="description"):
        checker().check_archive(wheel(tmp_path, summary="Old migration evaluator"))


def test_sdist_rejects_symlinks_without_extraction(tmp_path):
    path = tmp_path / "scenar-0.1.0.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("scenar-0.1.0/alias")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    with pytest.raises(ValueError, match="link"):
        checker().check_archive(path)


def sdist(tmp_path, source_wheel):
    path = tmp_path / "scenar-0.1.0.tar.gz"
    with zipfile.ZipFile(source_wheel) as source, tarfile.open(path, "w:gz") as archive:
        for name in source.namelist():
            if name.endswith("/entry_points.txt"):
                continue
            target = "PKG-INFO" if name.endswith("/METADATA") else "src/" + name
            if ".dist-info/licenses/" in name:
                target = name.split(".dist-info/licenses/", 1)[1]
            payload = source.read(name)
            member = tarfile.TarInfo("scenar-0.1.0/" + target)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return path


def test_sdist_retains_core_resources(tmp_path):
    report = checker().check_archive(sdist(tmp_path, wheel(tmp_path)))
    assert report == {"kind": "sdist", "files": 7, "license_declared": False}


def test_public_release_requires_project_license(tmp_path):
    with pytest.raises(ValueError, match="license is not declared"):
        checker().check_archive(wheel(tmp_path), require_license=True)


@pytest.mark.parametrize("source", [False, True])
@pytest.mark.parametrize("payload", [None, "", "Fixture project license terms"])
def test_public_release_requires_license_payload(tmp_path, source, payload):
    extra = {} if payload is None else {"scenar-0.1.0.dist-info/licenses/LICENSE": payload}
    path = wheel(
        tmp_path, extra, license_headers="License-Expression: MIT\nLicense-File: LICENSE\n"
    )
    if source:
        path = sdist(tmp_path, path)
    if payload:
        assert checker().check_archive(path, require_license=True)["license_declared"]
    else:
        with pytest.raises(ValueError, match="license file"):
            checker().check_archive(path, require_license=True)


def test_sdist_requires_top_level_directory(tmp_path):
    path = tmp_path / "scenar-0.1.0.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(tarfile.TarInfo("PKG-INFO"), io.BytesIO())
    with pytest.raises(ValueError, match="top-level directory"):
        checker().check_archive(path)
