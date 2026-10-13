"""The leakage guarantee + tier separation + injection rendering, enforced in CI.

If these fail, the benchmark is measuring the wrong thing. These are the most
important tests in the repo.
"""

from __future__ import annotations

import pytest

from prompts import (
    SYSTEM_PROMPTS,
    LeakageError,
    apply_injection,
    assert_no_leakage,
    render_prompt,
    render_tier0,
)

TIERS = (0, 1, 2)


def test_no_ground_truth_leaks_any_tier(dataset):
    for s in dataset.scenarios:
        for t in TIERS:
            assert_no_leakage(s, render_prompt(s, t))


def test_no_leak_in_injected_variants(dataset):
    for s in dataset.scenarios:
        if s.injection is None:
            continue
        inj = apply_injection(s)
        for t in TIERS:
            assert_no_leakage(inj, render_prompt(inj, t))


def test_label_rationale_never_present(dataset):
    for s in dataset.scenarios:
        rationale = s.ground_truth.label_rationale.lower()
        for t in TIERS:
            assert rationale not in render_prompt(s, t).lower()


def test_leakage_detector_actually_fires(dataset):
    s = dataset.scenarios[0]
    poisoned = render_prompt(s, 0) + "\n" + s.ground_truth.label_rationale
    with pytest.raises(LeakageError):
        assert_no_leakage(s, poisoned)

def test_tier0_excludes_identity_and_lineage(dataset):
    for s in dataset.scenarios:
        t0 = render_tier0(s.tier0)
        assert "IDENTITY & ASSET CONTEXT:" not in t0
        assert "PROCESS LINEAGE & PREVALENCE:" not in t0
        assert s.tier1.user_role not in t0
        assert s.tier2.parent_process not in t0
        assert s.tier2.grandparent_process not in t0
        if s.tier1.user_name not in s.tier0.command_line:
            assert s.tier1.user_name not in t0
        if s.tier2.egress_destination and s.tier2.egress_destination not in s.tier0.command_line:
            assert s.tier2.egress_destination not in t0
            
def test_tier_monotone_inclusion(dataset):
    """Higher tiers must contain everything lower tiers show (add, never remove)."""
    for s in dataset.scenarios:
        p0, p1, p2 = (render_prompt(s, t) for t in TIERS)
        assert s.tier0.command_line in p0 and s.tier0.command_line in p1 and s.tier0.command_line in p2
        assert s.tier1.user_role in p1 and s.tier1.user_role in p2
        assert s.tier1.user_role not in p0
        assert s.tier2.parent_process in p2
        assert s.tier2.parent_process not in p1


def test_injection_payload_appears_only_in_target_field(dataset):
    for s in dataset.scenarios:
        if s.injection is None:
            continue
        inj = apply_injection(s)
        rendered = render_prompt(inj, 0)
        assert s.injection.payload in rendered  # it IS in the telemetry (attack surface)
        # ...but the structured Tier-2 is untouched
        assert inj.tier2 == s.tier2


def test_prompt_variants_present():
    assert {"baseline", "analyst", "hardened"} <= set(SYSTEM_PROMPTS)
    for v in SYSTEM_PROMPTS.values():
        assert len(v.system) > 40
