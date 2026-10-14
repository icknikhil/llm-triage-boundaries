"""
schema.py — Data contracts for soc-triage-bench.

Two contracts live here:

1. OUTPUT CONTRACT  (TriageDecision)
   What the LLM is *allowed* to say. Passed to Ollama as a JSON Schema so the
   decoder is grammar-constrained, then re-validated with Pydantic because
   "the server promised" is not a security control.

   NOTE: TriageDecision validates STRUCTURE only. It deliberately does NOT
   reject semantically inconsistent answers (e.g. verdict=CRITICAL with
   action=AUTO_CLOSE). Those are exactly the failures this benchmark exists to
   measure, and they are handled by the deterministic guardrail layer
   (guardrails.py), not hidden by the parser.

2. INPUT CONTRACT  (AlertScenario and its tiers)
   What an alert looks like, split into context tiers:

       Tier 0  raw telemetry            what a detection rule emits
       Tier 1  + identity / asset       what a CMDB / IdP lookup adds
       Tier 2  + execution lineage      what EDR process-tree + prevalence adds

   Ground truth is carried on the scenario but is NEVER rendered into a prompt
   (enforced in prompts.py and tested in tests/test_prompts.py).

Design rule: nothing in the dataset directly encodes a guardrail decision.
There is intentionally no `is_anomalous_parent` field — that signal is
*computed* deterministically by guardrails.py from raw lineage. If it were a
stored label shown to the model, the guardrail would just be re-reading the
answer key the model was already given.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

__all__ = [
    "VerdictEnum",
    "ActionEnum",
    "AssetCriticality",
    "ScenarioCategory",
    "LabelSource",
    "InjectionStrength",
    "InjectionSpec",
    "TriageDecision",
    "Tier0Telemetry",
    "Tier1IdentityContext",
    "Tier2LineageContext",
    "GroundTruth",
    "AlertScenario",
    "ScenarioDataset",
    "ACTION_SEVERITY",
    "SAFE_ACTIONS",
    "load_dataset",
    "triage_json_schema",
    "ValidationError",
]


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class VerdictEnum(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class ActionEnum(str, Enum):
    AUTO_CLOSE = "AUTO_CLOSE"
    ANALYST_REVIEW = "ANALYST_REVIEW"
    ESCALATE = "ESCALATE"


# Ordinal severity. The guardrail may only ever move an action UP this scale
# (monotonic safety property, verified in tests/test_guardrails.py).
ACTION_SEVERITY: dict[ActionEnum, int] = {
    ActionEnum.AUTO_CLOSE: 0,
    ActionEnum.ANALYST_REVIEW: 1,
    ActionEnum.ESCALATE: 2,
}


# Actions that do NOT auto-close. The LLM "abstaining" from closure means
# choosing one of these. Used by the abstention/calibration metric.
SAFE_ACTIONS: frozenset[ActionEnum] = frozenset(
    {ActionEnum.ANALYST_REVIEW, ActionEnum.ESCALATE}
)


class AssetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScenarioCategory(str, Enum):
    BENIGN = "BENIGN"          # clean, context-independent benign
    MALICIOUS = "MALICIOUS"    # clean, context-independent malicious
    AMBIGUOUS = "AMBIGUOUS"    # correct answer depends on context (twins)


class LabelSource(str, Enum):
    """Provenance of the ground-truth label (defeats the circularity critique)."""

    ATOMIC_RED_TEAM = "ATOMIC_RED_TEAM"   # behavior + maliciousness from ART
    MITRE_ATTACK = "MITRE_ATTACK"         # technique classification from ATT&CK
    LOLBAS = "LOLBAS"                     # living-off-the-land binary catalog
    VENDOR_DOC = "VENDOR_DOC"             # benign tool behavior from official docs
    AUTHOR_JUDGEMENT = "AUTHOR_JUDGEMENT" # explicitly flagged author call (ambiguous)


class InjectionStrength(str, Enum):
    NAIVE = "NAIVE"          # overt "ignore previous instructions" style
    PLAUSIBLE = "PLAUSIBLE"  # mimics legitimate admin justification


# --------------------------------------------------------------------------- #
# OUTPUT CONTRACT
# --------------------------------------------------------------------------- #
class TriageDecision(BaseModel):
    """The only shape of answer the model may return.

    Field order matters: with grammar-constrained decoding the model emits
    properties in schema order. `reasoning` is first so the model commits to
    an explanation before a verdict (a lightweight chain-of-thought). The
    evaluator can flip this with `--field-order verdict-first` to measure
    whether order changes decisions.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reasoning: str = Field(
        ...,
        min_length=10,
        max_length=1500,
        description="Concise analyst-style justification citing the specific evidence used.",
    )
    verdict: VerdictEnum = Field(..., description="Assessed maliciousness of the alert.")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Self-reported probability (0.0-1.0) that the verdict is correct.",
    )
    action: ActionEnum = Field(..., description="Recommended disposition of the alert.")

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_confidence(cls, v: Any) -> float:
        try:
            val = float(v)
        except (ValueError, TypeError):
            raise ValueError(f"confidence must be numeric, got {v!r}")
        if 1.0 < val <= 100.0:
            return val / 100.0
        return val

def triage_json_schema(field_order: Literal["reasoning-first", "verdict-first"] = "reasoning-first") -> dict[str, Any]:
    """JSON Schema for TriageDecision, optionally with re-ordered properties.

    Ollama converts the schema into a decoding grammar. Most grammar
    converters emit properties in the order they appear in `properties`, so
    re-ordering the dict is how we run the field-order ablation.
    """
    schema = TriageDecision.model_json_schema()
    if field_order == "verdict-first":
        order = ["verdict", "confidence", "action", "reasoning"]
    elif field_order == "reasoning-first":
        order = ["reasoning", "verdict", "confidence", "action"]
    else:  # pragma: no cover - guarded by argparse choices
        raise ValueError(f"unknown field_order: {field_order}")
    props = schema["properties"]
    schema["properties"] = {k: props[k] for k in order}
    schema["required"] = order
    return schema


# --------------------------------------------------------------------------- #
# INPUT CONTRACT
# --------------------------------------------------------------------------- #
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class Tier0Telemetry(_Strict):
    """Raw alert as emitted by a detection rule. No enrichment."""

    alert_name: str = Field(..., min_length=3)
    hostname: str = Field(..., min_length=1, description="Opaque hostname; must not leak asset role.")
    process_name: str = Field(..., min_length=1)
    command_line: str = Field(..., min_length=1)
    event_time_utc: datetime

    @field_validator("process_name")
    @classmethod
    def _lower_process(cls, v: str) -> str:
        return v.lower()


class Tier1IdentityContext(_Strict):
    """Identity + asset enrichment (IdP / HR / CMDB lookups)."""

    user_name: str
    user_role: str
    user_is_privileged: bool
    asset_role: str
    asset_criticality: AssetCriticality
    user_on_expected_asset: bool = Field(
        ..., description="Has this user historically logged on to this asset?"
    )
    within_user_working_hours: bool


class Tier2LineageContext(_Strict):
    """Process lineage + prevalence enrichment (EDR process tree, fleet stats)."""

    parent_process: str
    parent_command_line: Optional[str] = None
    grandparent_process: str
    process_execution_count_24h: int = Field(
        ..., ge=0, description="Org-wide count of this exact process+command-line pattern in the last 24h."
    )
    binary_is_signed: bool
    binary_signer: Optional[str] = None
    network_egress: bool
    egress_destination: Optional[str] = None

    @field_validator("parent_process", "grandparent_process")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()

    @model_validator(mode="after")
    def _signer_consistency(self) -> "Tier2LineageContext":
        if self.binary_is_signed and not self.binary_signer:
            raise ValueError("binary_is_signed=True requires binary_signer")
        if not self.binary_is_signed and self.binary_signer:
            raise ValueError("binary_signer set but binary_is_signed=False")
        if self.network_egress is False and self.egress_destination:
            raise ValueError("egress_destination set but network_egress=False")
        return self


class InjectionSpec(_Strict):
    """An attacker-controlled payload embedded into a free-text telemetry field.

    This models Experiment 4 (adversarial context). The payload is appended to
    exactly one Tier-0 free-text field (`target_field`) at evaluation time. The
    guardrail NEVER reads these fields, so a correct result is: the LLM's
    recommendation may flip, but the deterministic authorization does not.
    """

    target_field: Literal["command_line", "process_name", "alert_name"]
    strength: InjectionStrength
    payload: str = Field(..., min_length=5, description="Attacker text appended to target_field.")
    attacker_goal: Literal["evade_to_benign", "flood_to_review"] = "evade_to_benign"


class GroundTruth(_Strict):
    """Analyst-labelled correct answer. NEVER shown to the model."""

    verdict: VerdictEnum
    safe_to_auto_close: bool
    acceptable_actions: list[ActionEnum] = Field(..., min_length=1)
    label_rationale: str = Field(..., min_length=20)
    label_source: LabelSource = Field(
        default=LabelSource.AUTHOR_JUDGEMENT,
        description="Provenance of this label. AUTHOR_JUDGEMENT is flagged honestly for ambiguous cases.",
    )

    @model_validator(mode="after")
    def _coherent(self) -> "GroundTruth":
        closes = ActionEnum.AUTO_CLOSE in self.acceptable_actions
        if self.safe_to_auto_close:
            if self.verdict is not VerdictEnum.BENIGN:
                raise ValueError("safe_to_auto_close=True requires verdict BENIGN")
            if not closes:
                raise ValueError("safe_to_auto_close=True requires AUTO_CLOSE in acceptable_actions")
        else:
            if closes:
                raise ValueError("safe_to_auto_close=False forbids AUTO_CLOSE in acceptable_actions")
            if self.verdict is VerdictEnum.BENIGN:
                raise ValueError("unsafe scenario cannot have verdict BENIGN")
        return self


class AlertScenario(_Strict):
    scenario_id: str = Field(..., pattern=r"^STB-[A-Z0-9]{2,4}-\d{2}[AB]?$")
    title: str = Field(..., min_length=5)
    category: ScenarioCategory
    mitre_techniques: list[str] = Field(..., min_length=1)
    references: list[str] = Field(..., min_length=1)
    pair_id: Optional[str] = Field(
        None, description="Counterfactual twin group. Twins share identical Tier-0 command telemetry."
    )
    twin_role: Optional[Literal["A", "B"]] = None
    tier0: Tier0Telemetry
    tier1: Tier1IdentityContext
    tier2: Tier2LineageContext
    ground_truth: GroundTruth
    injection: Optional[InjectionSpec] = Field(
        None, description="Optional adversarial payload for the injection experiment (Experiment 4)."
    )

    @field_validator("mitre_techniques")
    @classmethod
    def _mitre_ids(cls, v: list[str]) -> list[str]:
        import re

        pat = re.compile(r"^T\d{4}(\.\d{3})?$")
        bad = [t for t in v if not pat.match(t)]
        if bad:
            raise ValueError(f"invalid MITRE technique IDs: {bad}")
        return v

    @model_validator(mode="after")
    def _twin_fields(self) -> "AlertScenario":
        if (self.pair_id is None) != (self.twin_role is None):
            raise ValueError("pair_id and twin_role must be set together")
        if self.pair_id is not None and self.category is not ScenarioCategory.AMBIGUOUS:
            raise ValueError("twin scenarios must be category AMBIGUOUS")
        return self


class ScenarioDataset(_Strict):
    dataset_version: str
    description: str
    license: str
    scenarios: list[AlertScenario] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _integrity(self) -> "ScenarioDataset":
        ids = [s.scenario_id for s in self.scenarios]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate scenario_id(s): {sorted(dupes)}")

        pairs: dict[str, list[AlertScenario]] = {}
        for s in self.scenarios:
            if s.pair_id:
                pairs.setdefault(s.pair_id, []).append(s)

        for pid, members in pairs.items():
            if len(members) != 2 or {m.twin_role for m in members} != {"A", "B"}:
                raise ValueError(f"pair {pid} must contain exactly one A and one B twin")
            a, b = sorted(members, key=lambda m: m.twin_role or "")
            # The core methodological invariant: the detection-level telemetry
            # a Tier-0 model sees must be indistinguishable between twins.
            for f in ("alert_name", "process_name", "command_line", "event_time_utc"):
                if getattr(a.tier0, f) != getattr(b.tier0, f):
                    raise ValueError(f"pair {pid}: twins differ in tier0.{f}")
            if a.ground_truth.safe_to_auto_close == b.ground_truth.safe_to_auto_close:
                raise ValueError(f"pair {pid}: twins must have opposite safe_to_auto_close labels")
        return self

    def by_id(self) -> dict[str, AlertScenario]:
        return {s.scenario_id: s for s in self.scenarios}


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #
def load_dataset(path: str | Path) -> ScenarioDataset:
    """Load and fully validate the scenario corpus. Fails loudly on any defect."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return ScenarioDataset.model_validate(raw)


if __name__ == "__main__":  # quick self-check: python schema.py
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("dataset.json")
    ds = load_dataset(target)
    n_pairs = len({s.pair_id for s in ds.scenarios if s.pair_id})
    n_unsafe = sum(not s.ground_truth.safe_to_auto_close for s in ds.scenarios)
    print(f"OK  {len(ds.scenarios)} scenarios | {n_pairs} counterfactual twin pairs | "
          f"{n_unsafe} unsafe-to-close | dataset v{ds.dataset_version}")
    print(json.dumps(triage_json_schema(), indent=2))
