"""Integration tests: full adversarial cycle across components."""

from __future__ import annotations

from opensystem.attack.planner import default_planner
from opensystem.core.engine import AdversarialEngine
from opensystem.models import FindingStatus, TestOutcome


def test_full_attack_defend_evolve_cycle(store, mock_target):
    """Attack → findings → defenses → regressions → new attack surfaces."""
    engine = AdversarialEngine(store=store, planner=default_planner(store))

    results = engine.security_test(mock_target, rounds=5)

    r1 = results["first_round"]
    r2 = results["second_round"]

    # Round 1 found weaknesses.
    assert r1.findings_created == 5
    assert r1.successful_tests == 5

    # Defenses applied.
    assert len(results["defenses"]) == 5

    # Regressions: previously-exploitable weaknesses now blocked.
    assert len(results["regressions"]) == 5
    assert all(
        r.outcome == TestOutcome.FAILURE for r in results["regressions"]
    )

    # Round 2 evolved to the previously-untested attack surfaces.
    assert r2.experiments_run == 3
    assert r2.findings_created == 3

    untested_before = {"strategy:session-fixation",
                       "strategy:state-transition",
                       "strategy:dependency-supply-chain"}
    assert untested_before.issubset(r2.attack_classes_attempted)


def test_defenses_are_recorded_in_knowledge(store, mock_target):
    engine = AdversarialEngine(store=store, planner=default_planner(store))
    engine.security_test(mock_target, rounds=5)

    defenses = store.search_knowledge("Defense applied")
    assert len(defenses) == 5


def test_closed_findings_still_listed(store, mock_target, policy):
    engine = AdversarialEngine(
        store=store, policy=policy, planner=default_planner(store)
    )
    engine.research(mock_target, rounds=5)

    findings = store.list_findings()
    assert len(findings) == 5
    assert all(f.verification_status == FindingStatus.DISCOVERED for f in findings)

    # A finding that has been closed remains in history.
    engine.store.update_finding_status(findings[0].id, FindingStatus.CLOSED)
    still_there = store.list_findings()
    assert any(f.id == findings[0].id for f in still_there)
    assert len(store.open_findings()) == 4
