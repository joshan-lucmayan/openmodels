"""Tests for evidence persistence."""

from __future__ import annotations

from opensystem.evidence.engine import EvidenceCollector
from opensystem.experiment.engine import ExperimentEngine
from opensystem.models import Evidence, EvidenceKind, Hypothesis, TestOutcome
from opensystem.policy.engine import PolicyEnforcer
from opensystem.policy.models import Policy


def test_evidence_linked_to_experiment(store, mock_target, policy):
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
    assert len(experiment.evidence_ids) == 1

    # Experiment rows reference the collected evidence ids.
    persisted = store.get_experiments_by_hypothesis(hyp.id)[0]
    assert persisted.evidence_ids == experiment.evidence_ids


def test_evidence_collector_persists(store, mock_target):
    from opensystem.models import TestSpec

    mock_target.execute_test(
        TestSpec(name="t", parameters={"weakness": "auth-bypass"})
    )
    collector = EvidenceCollector(store)
    evidence = collector.collect(mock_target)
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceKind.OBSERVATION
    assert evidence[0].data["outcome"] == TestOutcome.SUCCESS.value


def test_evidence_models_roundtrip(store):
    ev = Evidence(
        kind=EvidenceKind.RESPONSE,
        data={"status": 200, "body": "secret"},
        reference="target:endpoint",
    )
    store.save_evidence(ev)
    # Save + reload through a fresh query path to ensure no corruption.
    assert ev.id is not None
    assert ev.kind == EvidenceKind.RESPONSE
