"""Source-level flow matching extracted from the existing evaluator."""

from __future__ import annotations

import math
from datetime import datetime, timedelta

from pydantic import AwareDatetime, Field, model_validator

from .models import Model, Record


class Permit(Model):
    id: str
    revision: int = Field(ge=1)
    available_at: AwareDatetime
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    host: str
    account: str
    input_path: str
    output_path: str
    destinations: list[str]

    @model_validator(mode="after")
    def valid_window(self) -> Permit:
        if self.valid_from >= self.valid_until:
            raise ValueError("Empty destination inventory validity")
        return self


def wire_available(r: Record, cutoff: datetime) -> bool:
    try:
        duration = float(r.data["duration"])
        return (
            math.isfinite(duration)
            and duration >= 0
            and r.time + timedelta(seconds=duration) <= cutoff
        )
    except (KeyError, ValueError, OverflowError):
        return False


def wire_matches(socket: Record, wire: Record) -> bool:
    pairs = (
        ("SourceIp", "id.orig_h"),
        ("SourcePort", "id.orig_p"),
        ("DestinationIp", "id.resp_h"),
        ("DestinationPort", "id.resp_p"),
        ("Protocol", "proto"),
    )
    return (
        wire.source == "zeek_conn"
        and all(
            socket.data.get(a) and socket.data[a].casefold() == wire.data.get(b, "").casefold()
            for a, b in pairs
        )
        and abs((socket.time - wire.time).total_seconds()) <= 5
    )
