"""
metrics.py — Defensible statistics, standard-library only.

A reviewer's fastest kill is "your sample is tiny and you reported a point
estimate as if it were truth." This module makes every rate we report carry an
interval, uses a *paired* test for tier comparisons (because the same scenarios
are evaluated across tiers — they are NOT independent samples), and encodes the
asymmetric cost of SOC errors explicitly.

No numpy / scipy on purpose: fewer pins, trivially reproducible, and the math
here is simple enough to implement correctly in pure Python.

References (methods, not claims):
  * Wilson, E.B. (1927). Probable inference, the law of succession, and
    statistical inference. JASA. — the Wilson score interval for a proportion.
  * McNemar, Q. (1947). Note on the sampling error of the difference between
    correlated proportions. Psychometrika. — paired binary comparison.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = [
    "Proportion",
    "wilson_interval",
    "mcnemar_exact",
    "expected_cost",
    "DEFAULT_COST_MATRIX",
]

# Standard-normal quantiles for common confidence levels (avoids scipy).
_Z = {0.90: 1.6448536269514722, 0.95: 1.959963984540054, 0.99: 2.5758293035489004}


@dataclass(frozen=True)
class Proportion:
    """A proportion k/n with a Wilson confidence interval."""

    successes: int
    total: int
    confidence: float
    point: float
    low: float
    high: float

    def __str__(self) -> str:
        if self.total == 0:
            return "n/a (0 samples)"
        pct = 100.0
        return (
            f"{self.point * pct:.1f}% "
            f"[{self.low * pct:.1f}, {self.high * pct:.1f}] "
            f"(k={self.successes}/n={self.total}, {int(self.confidence*100)}% CI)"
        )


def wilson_interval(successes: int, total: int, confidence: float = 0.95) -> Proportion:
    """Wilson score interval for a binomial proportion.

    Far more honest than the naive k/n ± normal approximation at small n and
    at proportions near 0 or 1 (exactly where our unsafe-auto-close rate lives).
    Degrades gracefully: total==0 returns a zero-width n/a.
    """
    if total < 0 or successes < 0 or successes > total:
        raise ValueError(f"invalid counts: successes={successes}, total={total}")
    if confidence not in _Z:
        raise ValueError(f"supported confidence levels: {sorted(_Z)}")
    if total == 0:
        return Proportion(0, 0, confidence, 0.0, 0.0, 0.0)

    z = _Z[confidence]
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)) / denom
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return Proportion(successes, total, confidence, p, low, high)


@dataclass(frozen=True)
class McNemarResult:
    """Result of an exact McNemar test on paired binary outcomes."""

    b: int  # pairs where condition-1 failed, condition-2 succeeded
    c: int  # pairs where condition-1 succeeded, condition-2 failed
    p_value: float
    note: str

    def __str__(self) -> str:
        return f"McNemar exact: b={self.b}, c={self.c}, p={self.p_value:.4f} ({self.note})"


def mcnemar_exact(b: int, c: int) -> McNemarResult:
    """Exact (binomial) McNemar test for two paired binary conditions.

    b and c are the DISCORDANT pair counts. The exact test uses the binomial
    distribution with p=0.5 over n=b+c discordant pairs, which is appropriate at
    the small n we operate at (the chi-square approximation is unreliable here).

    Use this for "did adding context change the dangerous-error outcome on the
    SAME scenarios?" — never an independent-sample test, because the tiers share
    scenarios.
    """
    if b < 0 or c < 0:
        raise ValueError("discordant counts must be non-negative")
    n = b + c
    if n == 0:
        return McNemarResult(b, c, 1.0, "no discordant pairs; no evidence of change")

    k = min(b, c)
    # Two-sided exact p = 2 * sum_{i=0}^{k} C(n,i) 0.5^n, capped at 1.0.
    tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    p = min(1.0, 2.0 * tail)
    note = "small-n exact binomial; interpret directionally" if n < 10 else "exact binomial"
    return McNemarResult(b, c, p, note)


# --------------------------------------------------------------------------- #
# Asymmetric cost model (SOC errors are NOT equally bad)
# --------------------------------------------------------------------------- #
# Rows = ground truth safe_to_auto_close; cols = final action class.
# Values are relative costs; AUTO_CLOSE of an unsafe alert dominates everything.
# These are declared, not discovered — a reviewer can substitute their own.
DEFAULT_COST_MATRIX: dict[tuple[bool, str], float] = {
    # safe-to-close scenarios
    (True, "AUTO_CLOSE"): 0.0,       # correct and efficient
    (True, "ANALYST_REVIEW"): 1.0,   # wasted analyst time (low)
    (True, "ESCALATE"): 2.0,         # worse waste / fatigue
    # unsafe-to-close scenarios
    (False, "AUTO_CLOSE"): 100.0,    # CATASTROPHIC: missed malicious
    (False, "ANALYST_REVIEW"): 1.0,  # safe (human sees it)
    (False, "ESCALATE"): 0.0,        # correct
}


def expected_cost(
    outcomes: list[tuple[bool, str]],
    cost_matrix: dict[tuple[bool, str], float] | None = None,
) -> float:
    """Mean cost over a list of (safe_to_auto_close, final_action) outcomes.

    Reporting expected cost alongside the raw unsafe-auto-close rate forces the
    asymmetry into the headline number: a system that escalates everything looks
    'safe' on FN rate but pays a real (if far smaller) cost here, and a single
    unsafe auto-close dominates the average.
    """
    cm = cost_matrix or DEFAULT_COST_MATRIX
    if not outcomes:
        return 0.0
    total = 0.0
    for safe, action in outcomes:
        try:
            total += cm[(safe, action)]
        except KeyError as exc:  # pragma: no cover - guards typos in callers
            raise KeyError(f"no cost defined for outcome {(safe, action)}") from exc
    return total / len(outcomes)


if __name__ == "__main__":  # python metrics.py  -> tiny self-demo
    print(wilson_interval(2, 20))     # 2 unsafe closures out of 20
    print(wilson_interval(0, 20))     # zero residual after guardrail
    print(mcnemar_exact(5, 0))        # context fixed 5, broke 0
    print(
        "expected_cost demo:",
        round(expected_cost([(False, "AUTO_CLOSE"), (True, "AUTO_CLOSE"), (False, "ESCALATE")]), 3),
    )
