"""Tests for the statistics helpers. If these are wrong, every reported number is
wrong, so they are verified against known values."""

from __future__ import annotations

import math

import pytest

from metrics import expected_cost, mcnemar_exact, wilson_interval


def test_wilson_zero_successes():
    p = wilson_interval(0, 20)
    assert p.point == 0.0
    assert p.low == 0.0
    assert p.high > 0.0          # upper bound is NOT zero at n=20 (the whole point)
    assert p.high < 0.20         # but it's a sane small number


def test_wilson_all_successes():
    p = wilson_interval(20, 20)
    assert p.point == 1.0
    assert p.high == 1.0
    assert p.low < 1.0


def test_wilson_known_value():
    # 10/20 = 0.5; Wilson 95% CI is approx [0.299, 0.701].
    p = wilson_interval(10, 20)
    assert math.isclose(p.point, 0.5, abs_tol=1e-9)
    assert abs(p.low - 0.299) < 0.01
    assert abs(p.high - 0.701) < 0.01


def test_wilson_empty():
    p = wilson_interval(0, 0)
    assert p.total == 0
    assert "n/a" in str(p)


def test_wilson_rejects_bad_counts():
    with pytest.raises(ValueError):
        wilson_interval(5, 3)


def test_mcnemar_no_discordance():
    r = mcnemar_exact(0, 0)
    assert r.p_value == 1.0


def test_mcnemar_strong_effect():
    # 8 improved, 0 regressed -> should be significant-ish (small-n exact).
    r = mcnemar_exact(8, 0)
    assert r.p_value < 0.05


def test_mcnemar_symmetric():
    assert mcnemar_exact(3, 3).p_value == pytest.approx(mcnemar_exact(3, 3).p_value)
    assert mcnemar_exact(5, 2).p_value == mcnemar_exact(2, 5).p_value


def test_expected_cost_dominated_by_unsafe_close():
    # one unsafe auto-close should dominate many minor over-escalations
    bad = expected_cost([(False, "AUTO_CLOSE")])
    noisy = expected_cost([(True, "ESCALATE")] * 10)
    assert bad > noisy


def test_expected_cost_all_correct_is_zero():
    assert expected_cost([(True, "AUTO_CLOSE"), (False, "ESCALATE")]) == 0.0
