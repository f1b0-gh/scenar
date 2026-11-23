"""EvidenceForge is an external, source-identified backend, never a renamed fork."""

import hashlib
import os
import subprocess
import tomllib
import warnings
from importlib.resources import files as resources
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .io import canonical, digest, files


class BackendIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    upstream: str = "https://github.com/Cisco-Talos/EvidenceForge"
    revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{40}$")
    upstream_verified: bool = Field(default=False, strict=True)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    package_version: str
    behavior_revision: int | None = Field(default=None, strict=True, ge=1)
    dependency_lock_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    schema_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


def inspect_backend(checkout: Path) -> BackendIdentity:
    for name in ("src/evidenceforge", "pyproject.toml", "uv.lock"):
        if not (checkout / name).exists():
            raise ValueError(f"Backend is missing {name}")
    source = files(checkout / "src/evidenceforge")
    for name in ("pyproject.toml", "uv.lock"):
        source["@" + name] = digest(checkout / name)
    commands = checkout / "commands/eforge"
    if commands.exists():
        source.update({"commands/" + k: v for k, v in files(commands).items()})
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    behavior = checkout / "src/evidenceforge/config/generation_behavior.yaml"
    return BackendIdentity(
        revision=revision.stdout.strip() if revision.returncode == 0 else None,
        source_sha256=hashlib.sha256(canonical(source)).hexdigest(),
        package_version=tomllib.loads((checkout / "pyproject.toml").read_text())["project"][
            "version"
        ],
        behavior_revision=yaml.safe_load(behavior.read_text())["current_revision"]
        if behavior.exists()
        else None,
        dependency_lock_sha256=digest(checkout / "uv.lock"),
    )


def check_backend(checkout: Path, pin: BackendIdentity) -> None:
    actual = inspect_backend(checkout)
    for key in ("source_sha256", "package_version", "behavior_revision", "dependency_lock_sha256"):
        if getattr(pin, key) != getattr(actual, key):
            raise ValueError(f"Backend identity mismatch: {key}")
    if pin.revision is not None and pin.revision != actual.revision:
        raise ValueError("Backend identity mismatch: revision")


def backend_path(value: Path | None = None) -> Path:
    if value:
        return value.resolve()
    root = os.environ.get("SCENAR_EVIDENCEFORGE")
    if not root and os.environ.get("EVIDENCEFORGE"):
        warnings.warn("EVIDENCEFORGE is deprecated; use SCENAR_EVIDENCEFORGE", stacklevel=2)
        root = os.environ["EVIDENCEFORGE"]
    if not root:
        raise ValueError("Set SCENAR_EVIDENCEFORGE or pass --backend to select a checkout")
    return Path(root).resolve()


def backend_command(checkout: Path, *args: str) -> list[str]:
    # A project-managed backend environment is independent of Scenar's environment.
    return ["uv", "run", "--locked", "--project", str(checkout), "eforge", *args]


def read_pin(path: Path) -> BackendIdentity:
    return BackendIdentity.model_validate_json(path.read_bytes())


def active_pin() -> BackendIdentity:
    return BackendIdentity.model_validate_json(
        (resources("scenar") / "resources/evidenceforge.json").read_bytes()
    )


def compare_backends(active: Path, candidate: Path) -> dict:
    left, right = inspect_backend(active), inspect_backend(candidate)
    return {
        "active": left.model_dump(),
        "candidate": right.model_dump(),
        "changed": [k for k in type(left).model_fields if getattr(left, k) != getattr(right, k)],
        "compatible": None,
        "note": "Identity comparison only; run the frozen native compatibility matrix before promotion.",
    }
