"""Private intent labels; behavior, authorization and maliciousness stay separate."""

from typing import Literal, Self

from pydantic import Field, model_validator

from .attack import Model

Intent = Literal["malicious", "benign", "unknown"]
TruthMode = Literal["behavior-only", "intent-aware"]


class IntentLabel(Model):
    intent: Intent = "unknown"
    rationale: str | None = None

    @model_validator(mode="after")
    def justified(self) -> Self:
        if self.intent != "unknown" and (not self.rationale or not self.rationale.strip()):
            raise ValueError("Known intent requires an explicit author/adjudicator rationale")
        return self

    @property
    def is_malicious(self) -> bool | None:
        return None if self.intent == "unknown" else self.intent == "malicious"


class GroundTruth(Model):
    mode: TruthMode = "behavior-only"
    labels: dict[str, IntentLabel] = Field(default_factory=dict)
    # Optional episode labels are resolved through exact private membership, never names.
    episodes: dict[str, IntentLabel] = Field(default_factory=dict)

    def resolve(self, record_id: str, episode_ids: list[str] | None = None) -> IntentLabel:
        if record_id in self.labels:
            return self.labels[record_id]
        values = [self.episodes.get(e, IntentLabel()) for e in episode_ids or []]
        if values and len({v.intent for v in values}) == 1:
            return IntentLabel(
                intent=values[0].intent,
                rationale="; ".join(v.rationale for v in values if v.rationale) or None,
            )
        return IntentLabel()

    def bind(self, members: dict[str, list[str]], observations: dict[str, str]) -> "GroundTruth":
        if set(self.labels) - members.keys():
            raise ValueError("Intent labels reference unknown authored actions")
        known_episodes = {e for values in members.values() for e in values}
        if set(self.episodes) - known_episodes:
            raise ValueError("Intent labels reference unknown episodes")
        return GroundTruth(
            mode=self.mode,
            labels={
                native: self.resolve(authored, members[authored])
                for authored, native in observations.items()
                if authored in members
            },
        )


class IntentPredictions(Model):
    decisions: dict[str, Literal["malicious", "benign", "abstain"]]


def grade_intent(truth: GroundTruth, predictions: IntentPredictions) -> dict:
    if truth.mode == "behavior-only":
        return {"enabled": False, "mode": truth.mode}
    if truth.episodes:
        raise ValueError("Resolve episode labels to native observations before intent grading")
    counts = {
        key: 0
        for key in (
            "true_positive",
            "false_positive",
            "true_negative",
            "false_negative",
            "known_truth",
            "unknown_truth",
            "unresolved_known",
            "predictions_on_unknown",
        )
    }
    for id in sorted(truth.labels.keys() | predictions.decisions.keys()):
        label = truth.labels.get(id, IntentLabel()).intent
        decision = predictions.decisions.get(id, "abstain")
        if label == "unknown":
            counts["unknown_truth"] += 1
            counts["predictions_on_unknown"] += decision != "abstain"
            continue
        counts["known_truth"] += 1
        if decision == "abstain":
            counts["unresolved_known"] += 1
        else:
            key = {
                ("malicious", "malicious"): "true_positive",
                ("benign", "malicious"): "false_positive",
                ("benign", "benign"): "true_negative",
                ("malicious", "benign"): "false_negative",
            }[label, decision]
            counts[key] += 1
    return {"enabled": True, "mode": truth.mode, **counts}


class AnnotatedEvent(Model):
    record_id: str = Field(min_length=1)
    authored_record_id: str | None
    intent_id: str | None
    emitted: bool = Field(strict=True)
    authored_intent: Intent
    is_malicious: bool | None = Field(strict=True)
    rationale: str | None


def authored_identity_map(
    raw: dict,
    *,
    required_ids: set[str] | None = None,
    authored_counts: dict[str, int] | None = None,
) -> dict[str, str | None]:
    """Forge numbers rendered events after sorting; join author order through its intent ledger."""
    required_steps = {id.rpartition("#")[0] for id in required_ids or set()}
    ledger = raw.get("intent_reconciliation")
    by_intent = {}
    if ledger is not None:
        counts = {}
        sections = {}
        for intent in ledger["intents"]:
            sid = intent["storyline_id"]
            iid = intent["intent_id"]
            if not isinstance(sid, str) or not isinstance(iid, str) or not iid or iid in by_intent:
                raise ValueError("Malformed or duplicate intent ledger identity")
            section = intent.get("ground_truth_section")
            if sid in sections and sections[sid] != section:
                raise ValueError("Ambiguous intent ledger step across sections")
            sections[sid] = section
            ordinal = counts.get(sid, 0)
            counts[sid] = ordinal + 1
            by_intent[iid] = f"{sid}#{ordinal}"
    native = raw["events"]
    if len({e["record_id"] for e in native}) != len(native):
        raise ValueError("Duplicate native record identity")
    counts = {}
    for event in native:
        sid = event.get("storyline_id") or event["record_id"].rpartition("#")[0]
        counts[sid] = counts.get(sid, 0) + 1
    result = {}
    for event in native:
        id = event["record_id"]
        sid = event.get("storyline_id") or id.rpartition("#")[0]
        if ledger is not None:
            authored = by_intent.get(event.get("intent_id"))
            if authored is not None and authored.rpartition("#")[0] != sid:
                raise ValueError("Intent ledger points to a different authored step")
            if authored is None and sid in required_steps:
                raise ValueError("Missing intent ledger reference for labeled step")
        elif counts[sid] == 1 and (authored_counts or {}).get(sid) == 1 and id == sid + "#0":
            authored = id
        else:
            if sid in required_steps:
                raise ValueError("Ambiguous authored order without an intent ledger")
            authored = None
        result[id] = authored
    return result


def annotate_native_truth(
    raw: dict,
    truth: GroundTruth,
    *,
    members: dict[str, list[str]] | None = None,
    authored_counts: dict[str, int] | None = None,
) -> dict:
    """A private overlay; never use rendered event ordinals as authored ordinals."""
    required = set(truth.labels) | (
        {id for id, episodes in (members or {}).items() if set(episodes) & truth.episodes.keys()}
    )
    identities = authored_identity_map(raw, required_ids=required, authored_counts=authored_counts)
    events = []
    seen = set()
    for event in raw["events"]:
        authored = identities[event["record_id"]]
        if authored is not None:
            seen.add(authored)
        label = (
            truth.resolve(authored, (members or {}).get(authored, []))
            if authored is not None
            else IntentLabel()
        )
        events.append(
            AnnotatedEvent(
                record_id=event["record_id"],
                authored_record_id=authored,
                intent_id=event.get("intent_id"),
                emitted=event["emitted"],
                authored_intent=label.intent,
                is_malicious=label.is_malicious if truth.mode == "intent-aware" else None,
                rationale=label.rationale,
            ).model_dump()
        )
    return {
        "schema": "scenar/ground-truth/v1",
        "mode": truth.mode,
        "events": events,
        "unrealized_labels": sorted(required - seen),
        "scope": "Author/adjudicator intent joined through the backend intent ledger. Emission is backend-reported; native qualification is separate. Unlabeled ambient events remain unknown.",
    }
