"""Tests for the experiment engine and lifecycle."""

from __future__ import annotations

from openmodels.experiment.engine import ExperimentEngine
from openmodels.models import Hypothesis, HypothesisStatus, TestOutcome
from openmodels.policy.engine import PolicyEnforcer
from openmodels.policy.models import Operation, Policy


def test_experiment_success_persisted(store, mock_target, policy):
    engine = ExperimentEngine(store, PolicyEnforcer(policy))
    target_model = mock_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="auth bypass possible",
        origin="strategy:auth-bypass",
        status=HypothesisStatus.ACTIVE,
    )
    store.save_hypothesis(hyp)

    experiment = engine.run(hyp, mock_target, target_model)
    assert experiment.outcome == TestOutcome.SUCCESS
    assert experiment.completed_at is not None
    assert experiment.openmodels_version == "0.1.0"

    persisted = store.get_experiments_by_hypothesis(hyp.id)
    assert len(persisted) == 1


def test_failed_experiment_is_retained(store, mock_target, policy):
    engine = ExperimentEngine(store, PolicyEnforcer(policy))
    target_model = mock_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="auth bypass possible",
        origin="strategy:auth-bypass",
    )
    store.save_hypothesis(hyp)

    mock_target.defend("auth-bypass")
    experiment = engine.run(hyp, mock_target, target_model)
    assert experiment.outcome == TestOutcome.FAILURE

    # A failed attack must remain in the record.
    assert len(store.get_experiments_by_hypothesis(hyp.id)) == 1


def test_experiment_records_conclusion(store, mock_target, policy):
    engine = ExperimentEngine(store, PolicyEnforcer(policy))
    target_model = mock_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="auth bypass possible",
        origin="strategy:auth-bypass",
    )
    store.save_hypothesis(hyp)
    experiment = engine.run(hyp, mock_target, target_model)
    assert "confirm" in experiment.conclusion.lower()


def test_policy_violation_blocks_experiment(store, mock_target):
    strict = Policy(
        target_name="mock",
        allowed_operations=[Operation.OBSERVE],
    )
    engine = ExperimentEngine(store, PolicyEnforcer(strict))
    target_model = mock_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="x",
        origin="strategy:auth-bypass",
    )
    store.save_hypothesis(hyp)

    from openmodels.policy.engine import PolicyViolation

    try:
        engine.run(hyp, mock_target, target_model)
        assert False, "expected PolicyViolation"
    except PolicyViolation:
        pass
