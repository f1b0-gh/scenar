"""Inspect core release archives for required resources and unintended local content.

This is an artifact-boundary check, not a license or comprehensive secret audit.
No archive member is extracted. Run after `uv build`:
    python tools/check_release.py dist/* --require-license
"""

from __future__ import annotations

import argparse
import configparser
import re
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

DESCRIPTION = "Scenar builds reproducible synthetic security datasets"
FORBIDDEN_PARTS = {
    ".local",
    ".git",
    ".aws",
    ".agents",
    ".codex",
    ".superpowers",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "target",
    "runs",
    "exports",
    "evidence",
    "node_modules",
}
REQUIRED_PACKAGE = {
    "__init__.py",
    "cli.py",
    "EVIDENCEFORGE-LICENSE.txt",
    "resources/evidenceforge.json",
    "resources/attack/catalog.json",
    "resources/attack/LICENSE.txt",
}
KEY_PATTERN = re.compile(rb"(?m)^-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\r?$")
ACCESS_KEY_PATTERN = re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")


def _name(name: str) -> str:
    if (
        name.startswith("/")
        or "\\" in name
        or ":" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError(f"Unsafe archive path: {name!r}")
    return name


def _members(path: Path) -> dict[str, bytes]:
    result = {}
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    _name(member.filename.rstrip("/"))
                    continue
                name = _name(member.filename)
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError(f"Archive link is not allowed: {name}")
                if name in result:
                    raise ValueError(f"Duplicate archive member: {name}")
                result[name] = archive.read(member)
    else:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                name = _name(member.name.rstrip("/"))
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f"Archive link/special file is not allowed: {name}")
                if name in result:
                    raise ValueError(f"Duplicate archive member: {name}")
                result[name] = archive.extractfile(member).read()
        roots = {name.split("/")[0] for name in result}
        if len(roots) != 1 or any("/" not in name for name in result):
            raise ValueError("Source archive must have one top-level directory")
        result = {name.split("/", 1)[1]: value for name, value in result.items()}
    return result


def check_archive(path: Path, *, require_license: bool = False) -> dict:
    members = _members(path)
    wheel = path.suffix == ".whl"
    for name, payload in members.items():
        parts = PurePosixPath(name).parts
        if (
            set(parts) & FORBIDDEN_PARTS
            or name.startswith(("bindings/", "datasets/"))
            or any(p == ".env" or (p.startswith(".env.") and p != ".env.example") for p in parts)
            or name.endswith((".pyc", ".pyo", ".log"))
        ):
            raise ValueError(f"Local or excluded content in release: {name}")
        if KEY_PATTERN.search(payload) or ACCESS_KEY_PATTERN.search(payload):
            raise ValueError(f"Possible credential material in archive member: {name}")
    prefix = "scenar/" if wheel else "src/scenar/"
    missing = {prefix + name for name in REQUIRED_PACKAGE} - members.keys()
    if missing:
        raise ValueError(f"Required resources/notices missing: {sorted(missing)}")
    metadata_names = (
        [n for n in members if n.endswith(".dist-info/METADATA")] if wheel else ["PKG-INFO"]
    )
    if len(metadata_names) != 1 or metadata_names[0] not in members:
        raise ValueError("Missing or ambiguous package metadata")
    metadata = BytesParser().parsebytes(members[metadata_names[0]])
    if metadata["Name"] != "scenar" or metadata["Summary"] != DESCRIPTION:
        raise ValueError("Package identity or description differs from Scenar release description")
    if wheel:
        entry_path = metadata_names[0].rsplit("/", 1)[0] + "/entry_points.txt"
        entries = configparser.ConfigParser()
        entries.read_string(members.get(entry_path, b"").decode())
        if entries.get("console_scripts", "scenar", fallback=None) != "scenar.cli:main":
            raise ValueError("Missing Scenar console entry point")
    declared = bool(metadata["License-Expression"] or metadata["License"])
    if require_license and not declared:
        raise ValueError("Project license is not declared; choose it before publication")
    if require_license:
        license_files = metadata.get_all("License-File", [])
        if "LICENSE" not in license_files:
            raise ValueError("Project license file LICENSE must be declared in package metadata")
        license_prefix = metadata_names[0].rsplit("/", 1)[0] + "/licenses/" if wheel else ""
        for name in license_files:
            member = license_prefix + _name(name)
            if not members.get(member, b"").strip():
                raise ValueError(f"Missing or empty project license file: {member}")
    return {
        "kind": "wheel" if wheel else "sdist",
        "files": len(members),
        "license_declared": declared,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", type=Path, nargs="+")
    parser.add_argument("--require-license", action="store_true")
    args = parser.parse_args()
    try:
        for path in args.archives:
            report = check_archive(path, require_license=args.require_license)
            print(f"{path.name}: {report}")
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"release check: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
