"""Tests for knowledge persistence and queries."""

from __future__ import annotations

from opensystem.models import (
    Experiment,
    Hypothesis,
    Knowledge,
    KnowledgeKind,
    TestOutcome,
    TestSpec,
)


def test_knowledge_persists_and_searches(store):
    store.save_knowledge(
        Knowledge(
            kind=KnowledgeKind.FAILED_STRATEGY,
            content="auth-bypass was blocked by a defense.",
            target_id="t1",
            provenance="test",
        )
    )
    results = store.search_knowledge("auth-bypass", target_id="t1")
    assert len(results) == 1
    assert results[0].kind == KnowledgeKind.FAILED_STRATEGY


def test_knowledge_search_across_targets(store):
    store.save_knowledge(Knowledge(kind=KnowledgeKind.ASSUMPTION, content="ssl is trusted"))
    store.save_knowledge(Knowledge(kind=KnowledgeKind.DEFENSE, content="mfa enforced"))
    assert len(store.search_knowledge("trusted")) == 1
    assert len(store.search_knowledge("enforced")) == 1


def test_previous_attempts_query(store):
    from opensystem.models import Hypothesis

    hyp = Hypothesis(target_id="t1", statement="x", origin="strategy:auth-bypass")
    store.save_hypothesis(hyp)
    for outcome in (TestOutcome.SUCCESS, TestOutcome.FAILURE):
        store.save_experiment(
            Experiment(
                hypothesis_id=hyp.id,
                target_id="t1",
                opensystem_version="0.1.0",
                test=TestSpec(name="t", parameters={"weakness": "auth-bypass"}),
                outcome=outcome,
            )
        )

    attempts = store.previous_attempts("t1")
    assert len(attempts) == 2
    # Newest first
    assert attempts[0].outcome == TestOutcome.FAILURE


def test_what_failed_query(store):
    from opensystem.models import Hypothesis

    hyp = Hypothesis(target_id="t1", statement="x", origin="strategy:auth-bypass")
    store.save_hypothesis(hyp)
    store.save_experiment(
        Experiment(
            hypothesis_id=hyp.id,
            target_id="t1",
            opensystem_version="0.1.0",
            test=TestSpec(name="t", parameters={"weakness": "auth-bypass"}),
            outcome=TestOutcome.FAILURE,
        )
    )
    failed = store.what_failed("t1")
    assert len(failed) == 1


def test_build_report(store):
    from opensystem.models import Hypothesis

    hyp = Hypothesis(target_id="t1", statement="x", origin="strategy:auth-bypass")
    store.save_hypothesis(hyp)
    store.save_experiment(
        Experiment(
            hypothesis_id=hyp.id,
            target_id="t1",
            opensystem_version="0.1.0",
            test=TestSpec(name="t", parameters={"weakness": "auth-bypass"}),
            outcome=TestOutcome.SUCCESS,
        )
    )
    report = store.build_report("t1")
    assert report.experiments_run == 1
    assert report.successful_tests == 1
    assert "auth-bypass" in report.attack_classes_attempted
