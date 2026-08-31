"""Tests for the adversarial loop (core engine)."""

from __future__ import annotations

from opensystem.models import TestOutcome


def test_research_loop_runs_experiments(engine, http_target):
    report = engine.research(http_target, rounds=5)
    assert report.experiments_run == 5
    assert report.hypotheses_formed >= 5
    assert report.findings_created >= 1
    assert report.rounds_executed == 5


def test_research_finds_real_vulnerabilities(engine, http_target):
    report = engine.research(http_target, rounds=11)
    assert report.findings_created >= 8
    assert report.successful_tests >= 8


def test_research_respects_policy_max_rounds(store, http_target, policy):
    from opensystem.attack.planner import default_planner
    from opensystem.core.engine import AdversarialEngine

    limited = policy.model_copy(update={"max_rounds": 3})
    engine = AdversarialEngine(
        store=store, policy=limited, planner=default_planner(store)
    )
    report = engine.research(http_target, rounds=10)
    assert report.experiments_run == 3
    assert report.stopped_reason == "POLICY_STOP"


def test_failed_experiment_recorded_in_what_failed(store):
    """A failed attack must be recorded in what_failed."""
    from opensystem.models import (
        Experiment,
        Hypothesis,
        TestSpec,
    )

    hyp = Hypothesis(target_id="t1", statement="x", origin="strategy:http-tls")
    store.save_hypothesis(hyp)
    store.save_experiment(
        Experiment(
            hypothesis_id=hyp.id,
            target_id="t1",
            opensystem_version="0.4.0",
            test=TestSpec(name="t", parameters={"weakness": "http-tls"}),
            outcome=TestOutcome.FAILURE,
        )
    )
    failures = store.what_failed("t1")
    assert len(failures) == 1
    assert failures[0].outcome == TestOutcome.FAILURE