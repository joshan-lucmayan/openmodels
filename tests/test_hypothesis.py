"""Tests for the hypothesis system."""

from __future__ import annotations

from opensystem.hypothesis.engine import HypothesisEngine
from opensystem.models import Hypothesis, HypothesisStatus, TestOutcome


def test_hypothesis_creation_and_persistence(store):
    hyp = Hypothesis(
        target_id="t1",
        statement="security headers can be missing",
        origin="strategy:http-security-headers",
    )
    engine = HypothesisEngine(store)
    engine.save(hyp)
    loaded = store.get_hypothesis(hyp.id)
    assert loaded is not None
    assert loaded.statement == hyp.statement
    assert loaded.status == HypothesisStatus.PROPOSED


def test_evaluate_success_accepts_hypothesis(store):
    hyp = Hypothesis(
        target_id="t1",
        statement="weakness exists",
        origin="strategy:http-sensitive-paths",
    )
    engine = HypothesisEngine(store)
    engine.save(hyp)

    from opensystem.models import Experiment, TestSpec

    exp = Experiment(
        hypothesis_id=hyp.id,
        target_id="t1",
        opensystem_version="0.4.0",
        test=TestSpec(name="t", parameters={"weakness": "http-sensitive-paths"}),
        outcome=TestOutcome.SUCCESS,
    )
    status = engine.evaluate(hyp, exp)
    assert status == HypothesisStatus.ACCEPTED
    assert store.get_hypothesis(hyp.id).status == HypothesisStatus.ACCEPTED


def test_evaluate_failure_rejects_hypothesis(store):
    hyp = Hypothesis(
        target_id="t1",
        statement="weakness exists",
        origin="strategy:http-sensitive-paths",
    )
    engine = HypothesisEngine(store)
    engine.save(hyp)

    from opensystem.models import Experiment, TestSpec

    exp = Experiment(
        hypothesis_id=hyp.id,
        target_id="t1",
        opensystem_version="0.4.0",
        test=TestSpec(name="t", parameters={"weakness": "http-sensitive-paths"}),
        outcome=TestOutcome.FAILURE,
    )
    status = engine.evaluate(hyp, exp)
    assert status == HypothesisStatus.REJECTED


def test_evaluate_inconclusive(store):
    hyp = Hypothesis(target_id="t1", statement="x", origin="strategy:unknown")
    engine = HypothesisEngine(store)
    engine.save(hyp)

    from opensystem.models import Experiment, TestSpec

    exp = Experiment(
        hypothesis_id=hyp.id,
        target_id="t1",
        opensystem_version="0.4.0",
        test=TestSpec(name="t"),
        outcome=TestOutcome.INCONCLUSIVE,
    )
    assert engine.evaluate(hyp, exp) == HypothesisStatus.INCONCLUSIVE