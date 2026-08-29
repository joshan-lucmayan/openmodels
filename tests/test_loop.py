"""Tests for the adversarial loop (core engine)."""

from __future__ import annotations

from openmodels.models import HypothesisStatus, TestOutcome


def test_research_loop_runs_experiments(engine, mock_target):
    report = engine.research(mock_target, rounds=5)
    assert report.experiments_run == 5
    assert report.hypotheses_formed >= 5
    assert report.findings_created >= 1
    assert report.rounds_executed == 5


def test_research_finds_all_seeded_weaknesses(engine, mock_target):
    # Running enough rounds to cover every seeded weakness.
    report = engine.research(mock_target, rounds=8)
    assert report.findings_created == 8
    assert report.successful_tests == 8


def test_research_respects_policy_max_rounds(store, mock_target, policy):
    from openmodels.attack.planner import default_planner
    from openmodels.core.engine import AdversarialEngine

    limited = policy.model_copy(update={"max_rounds": 3})
    engine = AdversarialEngine(
        store=store, policy=limited, planner=default_planner(store)
    )
    report = engine.research(mock_target, rounds=10)
    assert report.experiments_run == 3
    assert report.stopped_reason == "POLICY_STOP"


def test_learning_from_failure(engine, mock_target):
    """A failed attack must be recorded, and the hypothesis marked rejected."""
    target_model = mock_target.discover()
    store = engine.store

    mock_target.defend("auth-bypass")
    report = engine.research(mock_target, rounds=2)

    hypotheses = store.list_hypotheses(target_model.id)
    blocked_hyps = [
        h for h in hypotheses
        if h.origin == "strategy:auth-bypass"
    ]
    assert len(blocked_hyps) == 1
    assert blocked_hyps[0].status == HypothesisStatus.REJECTED

    # The blocked attack is still in the experiment record.
    failures = store.what_failed(target_model.id)
    assert any(e.outcome == TestOutcome.FAILURE for e in failures)


def test_evolution_generates_new_hypothesis_after_block(engine, mock_target):
    target_model = mock_target.discover()
    store = engine.store

    # Block several paths so evolution must pick an alternate.
    for key in ("auth-bypass", "authz-ownership", "input-traversal"):
        mock_target.defend(key)

    engine.research(mock_target, rounds=8)

    events = store.list_evolution_events()
    # Failure-driven evolution events should have been recorded.
    assert len(events) >= 1
