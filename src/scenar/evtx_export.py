"""Public EVTX encoding through an independently pinned external EvidenceForge CLI."""

import os
import signal
from pathlib import Path
from subprocess import DEVNULL, CalledProcessError, Popen, TimeoutExpired
from typing import Literal

from pydantic import Field

from .backend import BackendIdentity, backend_command
from .bundle import Artifact, Model
from .io import digest

WINDOWS_XML = frozenset({"windows_event_security.xml", "windows_event_sysmon.xml"})


class Conversion(Model):
    source: Artifact
    output: Artifact


class ExportReceipt(Model):
    schema_id: Literal["scenar/evtx-export/v1"] = Field(
        default="scenar/evtx-export/v1", alias="schema"
    )
    source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encoder: BackendIdentity
    conversions: list[Conversion]


def run_encoder_command(
    command: list[str], *, cwd: Path, timeout: float, env: dict[str, str]
) -> None:
    """Bound the complete uv/encoder process group, including timeout cleanup."""
    if os.name != "posix":
        raise ValueError("EVTX export requires POSIX process-group timeout handling")
    with Popen(command, cwd=cwd, env=env, stdout=DEVNULL, start_new_session=True) as process:
        try:
            status = process.wait(timeout=timeout)
        except TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        if status:
            raise CalledProcessError(status, command)


def encode_windows(source: Path, output: Path, backend: Path, timeout: float) -> None:
    """Run the external writer; never import EvidenceForge into Scenar's runtime."""
    environment = os.environ.copy()
    environment.pop("UV_PROJECT_ENVIRONMENT", None)
    run_encoder_command(
        backend_command(backend, "export-evtx", str(source.resolve()), str(output.resolve())),
        cwd=backend,
        timeout=timeout,
        env=environment,
    )
    if output.is_symlink():
        raise ValueError("Symlink in encoder output")
    if not output.is_file():
        raise ValueError("Encoder output must be a regular EVTX file")
    with output.open("rb") as stream:
        if stream.read(8) != b"ElfFile\x00":
            raise ValueError("EvidenceForge output is not an EVTX file")


def output_artifact(path: Path, relative: str) -> Artifact:
    return Artifact(path=relative, sha256=digest(path), size=path.stat().st_size)
