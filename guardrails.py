"""
guardrails.py — The deterministic authorization layer (the SAFETY BOUNDARY).

Thesis: the LLM RECOMMENDS; this policy AUTHORIZES. A probabilistic model may
propose any action, but autonomous closure is granted only when a deterministic
policy independently establishes it from STRUCTURED, sensor-attributed signals.

THREE PROPERTIES, each tested in tests/test_guardrails.py:

  1. STRONG AUTHORIZATION INVARIANT
       final == AUTO_CLOSE  ==>  (model proposed AUTO_CLOSE)
                                  AND (no hard structured signal fired)
     i.e. the policy never *grants* a closure the model didn't ask for, and
     never lets a closure through when a hard signal is present. Verified by
     exhaustive enumeration of the finite decision space (this is exhaustive
     TESTING over a finite domain, not a formal proof — stated honestly).

  2. MONOTONICITY
       final_severity >= model_severity  (can only move toward review/escalate).

  3. INJECTION INVARIANCE (the security result)
       The policy reads ONLY typed structured fields (parent/grandparent/
       prevalence/egress/signing). It NEVER reads command_line, process_name,
       or alert_name — the attacker-controlled free text. Therefore its output
       is invariant to any prompt-injection payload placed in those fields.
       compute_signals() does not even take the free text as an argument for the
       anomalous-parent decision beyond the already-structured process identity.

AVAILABILITY-ATTACK NOTE (reported, not hidden): because the policy only ever
RAISES severity, an attacker who can make benign activity *look* anomalous to
the structured signals could push benign alerts into the human queue (a DoS on
analysts, goal G2 in THREAT_MODEL.md). We surface this as a known limitation;
the monotonic design optimizes against missed attacks (G1) at the cost of this
availability surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from schema import (
    ACTION_SEVERITY,
    ActionEnum,
    AlertScenario,
    Tier2LineageContext,
    TriageDecision,
    VerdictEnum,
)

__all__ = [
    "GuardrailSignals",
    "GuardrailOutcome",
    "compute_signals",
    "apply_guardrail",
    "RARE_PREVALENCE_THRESHOLD",
]


# --------------------------------------------------------------------------- #
# Derived-signal policy tables (detection-engineering logic, not an answer key)
# --------------------------------------------------------------------------- #
_ANOMALOUS_PARENT_CHILD: dict[str, frozenset[str]] = {
    "w3wp.exe": frozenset({"powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe"}),
    "winword.exe": frozenset({"powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe", "wscript.exe"}),
    "excel.exe": frozenset({"powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe", "wscript.exe"}),
    "outlook.exe": frozenset({"powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe"}),
    "wmiprvse.exe": frozenset({"cmd.exe", "powershell.exe", "rundll32.exe", "mshta.exe"}),
    "services.exe": frozenset({"powershell.exe", "mshta.exe", "certutil.exe"}),
}

_ANOMALOUS_GRANDPARENTS: frozenset[str] = frozenset(
    {"wmiprvse.exe", "psexesvc.exe", "winrshost.exe"}
)

_DYNAMIC_DNS_SUFFIXES: tuple[str, ...] = (
    ".ddns.net", ".no-ip.org", ".duckdns.org", ".hopto.org", ".serveo.net",
)

RARE_PREVALENCE_THRESHOLD: int = 2


@dataclass(frozen=True)
class GuardrailSignals:
    is_anomalous_parent: bool
    is_rare_in_fleet: bool
    is_dynamic_dns_egress: bool
    is_raw_ip_egress: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def any_hard_signal(self) -> bool:
        """Hard = high-confidence 'must not auto-close' structured signals.

        Note: rarity alone is intentionally NOT 'hard' (benign-but-rare exists);
        it contributes context but does not by itself block closure.
        """
        return (
            self.is_anomalous_parent
            or self.is_dynamic_dns_egress
            or self.is_raw_ip_egress
        )


def _is_raw_ip(dest: str | None) -> bool:
    if not dest:
        return False
    parts = dest.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_dynamic_dns(dest: str | None) -> bool:
    if not dest:
        return False
    d = dest.lower()
    return any(d.endswith(s) for s in _DYNAMIC_DNS_SUFFIXES)


def compute_signals(tier2: Tier2LineageContext, child_process_name: str) -> GuardrailSignals:
    """Derive signals from STRUCTURED lineage only.

    `child_process_name` is the Tier-0 process identity (already lower-cased by
    the schema). Even though this is nominally 'from Tier-0', it is the TYPED
    process name, not the free-text command_line/alert_name that carries an
    injection payload. The injection experiment appends to command_line (or
    alert_name), neither of which is read here — hence injection invariance.
    """
    child = child_process_name.lower()
    parent = tier2.parent_process.lower()
    grandparent = tier2.grandparent_process.lower()

    reasons: list[str] = []

    anomalous_parent = child in _ANOMALOUS_PARENT_CHILD.get(parent, frozenset())
    if anomalous_parent:
        reasons.append(f"anomalous parent->child relationship: {parent} -> {child}")

    if grandparent in _ANOMALOUS_GRANDPARENTS:
        anomalous_parent = True
        reasons.append(f"remote-execution grandparent observed: {grandparent}")

    rare = tier2.process_execution_count_24h <= RARE_PREVALENCE_THRESHOLD
    if rare:
        reasons.append(
            f"rare in fleet: {tier2.process_execution_count_24h} executions/24h "
            f"(<= {RARE_PREVALENCE_THRESHOLD})"
        )

    ddns = _is_dynamic_dns(tier2.egress_destination)
    if ddns:
        reasons.append(f"egress to dynamic-DNS destination: {tier2.egress_destination}")

    raw_ip = _is_raw_ip(tier2.egress_destination)
    if raw_ip:
        reasons.append(f"egress to raw IP literal: {tier2.egress_destination}")

    return GuardrailSignals(
        is_anomalous_parent=anomalous_parent,
        is_rare_in_fleet=rare,
        is_dynamic_dns_egress=ddns,
        is_raw_ip_egress=raw_ip,
        reasons=tuple(reasons),
    )


@dataclass(frozen=True)
class GuardrailOutcome:
    original_action: ActionEnum
    final_action: ActionEnum
    guardrail_triggered: bool
    authorized_close: bool
    in_coverage: bool
    signals: GuardrailSignals
    override_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "original_action": self.original_action.value,
            "final_action": self.final_action.value,
            "guardrail_triggered": self.guardrail_triggered,
            "authorized_close": self.authorized_close,
            "in_coverage": self.in_coverage,
            "override_reason": self.override_reason,
            "signals": {
                "is_anomalous_parent": self.signals.is_anomalous_parent,
                "is_rare_in_fleet": self.signals.is_rare_in_fleet,
                "is_dynamic_dns_egress": self.signals.is_dynamic_dns_egress,
                "is_raw_ip_egress": self.signals.is_raw_ip_egress,
                "reasons": list(self.signals.reasons),
            },
        }


def _raise_to(current: ActionEnum, floor: ActionEnum) -> ActionEnum:
    return current if ACTION_SEVERITY[current] >= ACTION_SEVERITY[floor] else floor


def apply_guardrail(decision: TriageDecision, scenario: AlertScenario) -> GuardrailOutcome:
    """Authorize (or refuse) the model's proposed action from structured signals.

    Rules (each can only RAISE severity => monotonic):
      R1 anomalous lineage            -> floor ANALYST_REVIEW
      R2 CRITICAL + AUTO_CLOSE        -> floor ESCALATE   (incoherent closure)
      R3 untrusted egress (raw-IP/ddns) on attempted AUTO_CLOSE -> floor ANALYST_REVIEW

    Strong invariant guaranteed by construction:
      final == AUTO_CLOSE  iff  decision.action == AUTO_CLOSE AND not any_hard_signal
      (R2 also prevents CRITICAL auto-close even if no structured signal fired.)
    """
    signals = compute_signals(scenario.tier2, scenario.tier0.process_name)

    final = decision.action
    reasons: list[str] = []

    if signals.is_anomalous_parent and ACTION_SEVERITY[final] < ACTION_SEVERITY[ActionEnum.ANALYST_REVIEW]:
        final = _raise_to(final, ActionEnum.ANALYST_REVIEW)
        reasons.append("R1: anomalous parent lineage forbids auto-close")

    if decision.verdict is VerdictEnum.CRITICAL and decision.action is ActionEnum.AUTO_CLOSE:
        final = _raise_to(final, ActionEnum.ESCALATE)
        reasons.append("R2: verdict CRITICAL cannot be auto-closed; escalated")

    if decision.action is ActionEnum.AUTO_CLOSE and (signals.is_raw_ip_egress or signals.is_dynamic_dns_egress):
        final = _raise_to(final, ActionEnum.ANALYST_REVIEW)
        reasons.append("R3: untrusted egress destination forbids auto-close")

    triggered = ACTION_SEVERITY[final] > ACTION_SEVERITY[decision.action]
    authorized_close = final is ActionEnum.AUTO_CLOSE
    # "In coverage" = the policy had a structured signal to act on. If an unsafe
    # scenario fires NO hard signal, the policy is a no-op (the coverage gap).
    in_coverage = signals.any_hard_signal

    return GuardrailOutcome(
        original_action=decision.action,
        final_action=final,
        guardrail_triggered=triggered,
        authorized_close=authorized_close,
        in_coverage=in_coverage,
        signals=signals,
        override_reason="; ".join(reasons) if reasons else None,
    )


if __name__ == "__main__":  # python guardrails.py -> signal table
    from pathlib import Path
    from schema import load_dataset

    ds = load_dataset(Path(__file__).with_name("dataset.json"))
    print(f"{'scenario':<16}{'anom':<6}{'rare':<6}{'ddns':<6}{'rawip':<6}{'hard':<6} reasons")
    for s in ds.scenarios:
        sig = compute_signals(s.tier2, s.tier0.process_name)
        print(
            f"{s.scenario_id:<16}{str(sig.is_anomalous_parent):<6}"
            f"{str(sig.is_rare_in_fleet):<6}{str(sig.is_dynamic_dns_egress):<6}"
            f"{str(sig.is_raw_ip_egress):<6}{str(sig.any_hard_signal):<6} "
            f"{'; '.join(sig.reasons) or '-'}"
        )
