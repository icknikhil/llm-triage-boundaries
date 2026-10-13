"""Dataset integrity — the research invariants the corpus must satisfy."""

from __future__ import annotations

from schema import InjectionStrength, LabelSource, ScenarioCategory


def test_dataset_size(dataset):
    assert len(dataset.scenarios) >= 24


def test_category_balance(dataset):
    counts = {c: 0 for c in ScenarioCategory}
    for s in dataset.scenarios:
        counts[s.category] += 1
    assert counts[ScenarioCategory.BENIGN] >= 8
    assert counts[ScenarioCategory.MALICIOUS] >= 8
    assert counts[ScenarioCategory.AMBIGUOUS] >= 8


def test_at_least_four_twin_pairs(dataset):
    pair_ids = {s.pair_id for s in dataset.scenarios if s.pair_id}
    assert len(pair_ids) >= 4


def test_twins_share_tier0_opposite_truth(dataset):
    pairs: dict[str, list] = {}
    for s in dataset.scenarios:
        if s.pair_id:
            pairs.setdefault(s.pair_id, []).append(s)
    for pid, members in pairs.items():
        assert len(members) == 2
        a, b = members
        assert a.tier0.command_line == b.tier0.command_line
        assert a.tier0.process_name == b.tier0.process_name
        assert a.tier0.alert_name == b.tier0.alert_name
        assert a.tier0.event_time_utc == b.tier0.event_time_utc
        assert a.ground_truth.safe_to_auto_close != b.ground_truth.safe_to_auto_close


def test_every_scenario_cited(dataset):
    for s in dataset.scenarios:
        assert s.references
        assert all(r.startswith("http") for r in s.references)


def test_label_provenance_present(dataset):
    for s in dataset.scenarios:
        assert isinstance(s.ground_truth.label_source, LabelSource)


def test_malicious_cases_cite_attack_sources(dataset):
    """Malicious labels should inherit provenance from public sources, not be pure
    author opinion — defeats the circularity critique for the non-ambiguous set."""
    external = {LabelSource.ATOMIC_RED_TEAM, LabelSource.MITRE_ATTACK, LabelSource.LOLBAS}
    for s in dataset.scenarios:
        if s.category is ScenarioCategory.MALICIOUS:
            assert s.ground_truth.label_source in external, (
                f"{s.scenario_id} malicious label should be externally sourced"
            )


def test_unsafe_never_benign(dataset):
    for s in dataset.scenarios:
        if not s.ground_truth.safe_to_auto_close:
            assert s.ground_truth.verdict.value != "BENIGN"


def test_injection_specs_valid(dataset):
    found_naive = found_plausible = False
    for s in dataset.scenarios:
        if s.injection is None:
            continue
        assert s.injection.target_field in ("command_line", "process_name", "alert_name")
        assert len(s.injection.payload) >= 5
        if s.injection.strength is InjectionStrength.NAIVE:
            found_naive = True
        if s.injection.strength is InjectionStrength.PLAUSIBLE:
            found_plausible = True
    assert found_naive, "need at least one NAIVE injection case"
    assert found_plausible, "need at least one PLAUSIBLE injection case"
