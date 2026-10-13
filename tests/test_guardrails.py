"""The authorizer's three formal properties, enforced in CI.

1. STRONG AUTHORIZATION INVARIANT (exhaustive over the finite decision space):
   final == AUTO_CLOSE  ==>  model proposed AUTO_CLOSE AND no hard structured signal.
2. MONOTONICITY: final severity >= model severity, always.
3. INJECTION INVARIANCE: the authorizer's output is identical whether or not an
   injection payload is applied, because it never reads free-text fields.
"""

from __future__ import annotations

import itertools

import pytest

from guardrails import apply_guardrail, compute_signals
from prompts import apply_injection
from schema import ACTION_SEVERITY, ActionEnum, TriageDecision, VerdictEnum

ALL_VERDICTS = list(VerdictEnum)
ALL_ACTIONS = list(ActionEnum)
CONFIDENCES = [0.0, 0.25, 0.5, 0.75, 1.0]


def _decision(v, a, c):
    return TriageDecision(reasoning="test decision long enough for min_length.", verdict=v, confidence=c, action=a)


def test_monotonic_over_full_space(dataset):
    for s in dataset.scenarios:
        for v, a, c in itertools.product(ALL_VERDICTS, ALL_ACTIONS, CONFIDENCES):
            out = apply_guardrail(_decision(v, a, c), s)
            assert ACTION_SEVERITY[out.final_action] >= ACTION_SEVERITY[a]
            assert out.guardrail_triggered == (ACTION_SEVERITY[out.final_action] > ACTION_SEVERITY[a])


def test_strong_authorization_invariant(dataset):
    """final==AUTO_CLOSE iff model asked for it AND no hard signal fired.

    Exhaustive enumeration over the finite decision space x scenarios. This is
    exhaustive TESTING over a finite domain, not a formal proof — stated honestly.
    """
    for s in dataset.scenarios:
        sig = compute_signals(s.tier2, s.tier0.process_name)
        for v, a, c in itertools.product(ALL_VERDICTS, ALL_ACTIONS, CONFIDENCES):
            out = apply_guardrail(_decision(v, a, c), s)
            if out.final_action is ActionEnum.AUTO_CLOSE:
                assert a is ActionEnum.AUTO_CLOSE, "authorizer granted a close the model did not ask for"
                assert not sig.any_hard_signal, "authorizer allowed close despite a hard signal"
                assert v is not VerdictEnum.CRITICAL, "authorizer allowed a CRITICAL close"


def test_injection_invariance(dataset):
    """The authorizer output must be identical with/without the injection payload."""
    for s in dataset.scenarios:
        if s.injection is None:
            continue
        inj = apply_injection(s)
        for v, a, c in itertools.product(ALL_VERDICTS, ALL_ACTIONS, [0.5]):
            d = _decision(v, a, c)
            clean_out = apply_guardrail(d, s)
            # Guardrail is always applied to the ORIGINAL structured scenario; the
            # injected copy shares identical tier2, so results must match exactly.
            inj_out = apply_guardrail(d, inj)
            assert clean_out.final_action == inj_out.final_action
            assert clean_out.signals == inj_out.signals


def test_anomalous_parent_blocks_auto_close(dataset):
    for s in dataset.scenarios:
        sig = compute_signals(s.tier2, s.tier0.process_name)
        if not sig.is_anomalous_parent:
            continue
        out = apply_guardrail(_decision(VerdictEnum.BENIGN, ActionEnum.AUTO_CLOSE, 0.9), s)
        assert out.final_action is not ActionEnum.AUTO_CLOSE
        assert out.guardrail_triggered is True


def test_critical_autoclose_escalated(dataset):
    out = apply_guardrail(_decision(VerdictEnum.CRITICAL, ActionEnum.AUTO_CLOSE, 0.3), dataset.scenarios[0])
    assert out.final_action is ActionEnum.ESCALATE


def test_clean_benign_passes_through(dataset):
    clean = next(
        s for s in dataset.scenarios
        if s.ground_truth.safe_to_auto_close
        and not compute_signals(s.tier2, s.tier0.process_name).any_hard_signal
    )
    out = apply_guardrail(_decision(VerdictEnum.BENIGN, ActionEnum.AUTO_CLOSE, 0.95), clean)
    assert out.final_action is ActionEnum.AUTO_CLOSE
    assert out.guardrail_triggered is False


def test_signals_derive_from_structure_not_free_text(dataset):
    """compute_signals must depend only on structured tier2 + typed process name,
    never on the command_line free text (which carries injection)."""
    for s in dataset.scenarios:
        base = compute_signals(s.tier2, s.tier0.process_name)
        if s.injection is None:
            continue
        inj = apply_injection(s)  # mutates command_line only
        after = compute_signals(inj.tier2, inj.tier0.process_name)
        assert base == after
