"""As-of public observation adapter; private labels are forbidden."""

from . import wire as followup
from .models import Approval, Grant, Record, Snapshot


def adapt(public, start):
    """Pure schema adapter. No case family, labels or scenario metadata accepted."""
    if set(public) != {"as_of", "records", "permissions"}:
        raise ValueError("Unexpected public envelope")
    endpoint, wire = [], []
    for row in public["records"]:
        if set(row) != {"id", "source", "event_id", "host", "time", "data"}:
            raise ValueError("Unexpected record envelope")
        if row["source"] == "zeek_dns":
            # Existing policy schema has no DNS input; retain original in public archive.
            continue
        record = Record.model_validate({**row, "data": {k: str(v) for k, v in row["data"].items()}})
        (wire if row["source"] == "zeek_conn" else endpoint).append(record)
    approvals, permits = [], []
    for p in public["permissions"]:
        scope = p["scope"]
        inputs, outputs = scope["input_paths"], scope["output_paths"]
        if not inputs and not outputs:
            continue  # Network permissions cannot become endpoint action grants.
        if len(inputs) != 1 or len(outputs) != 1 or len(scope["accounts"]) != 1:
            raise ValueError("Cannot project ambiguous endpoint scope")
        timing = {k: p[k] for k in ("available_at", "valid_from", "valid_until")}
        approvals.append(
            Approval(
                id=p["id"],
                revision=1,
                **timing,
                account=scope["accounts"][0],
                hosts=scope["hosts"],
                grants=[
                    Grant(action="inventory", input_path=inputs[0]),
                    Grant(action="archive", input_path=inputs[0], output_path=outputs[0]),
                ],
            )
        )
        for host in scope["hosts"]:
            permits.append(
                followup.Permit(
                    id=p["id"] + ":" + host,
                    revision=1,
                    **timing,
                    host=host,
                    account=scope["accounts"][0],
                    input_path=inputs[0],
                    output_path=outputs[0],
                    destinations=scope["destinations"],
                )
            )
    snapshot = Snapshot(start=start, as_of=public["as_of"], records=endpoint, approvals=approvals)
    if any(r.time > snapshot.as_of for r in endpoint + wire):
        raise ValueError("Future observation in as-of input")
    return snapshot, wire, permits
