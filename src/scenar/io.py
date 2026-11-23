"""Deterministic artifacts and constrained paths."""

import hashlib
import json
import os
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".scenar-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(value, indent=2, allow_nan=False) + "\n")
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def safe_path(root: Path, relative: str) -> Path:
    p = PurePosixPath(relative)
    if (
        not relative
        or p.is_absolute()
        or "\\" in relative
        or ":" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise ValueError(f"Unsafe artifact path: {relative!r}")
    target = root / relative
    for parent in (target, *target.parents):
        if parent == root.parent:
            break
        if parent.is_symlink():
            raise ValueError(f"Symlink in artifact path: {relative!r}")
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Artifact escapes destination: {relative!r}")
    return target


def files(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError(f"Symlink in source: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path)
    return result
