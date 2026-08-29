"""Tests for the finding lifecycle."""

from __future__ import annotations

import pytest

from opensystem.finding.engine import FindingEngine
from opensystem.models import (
    Experiment,
    FindingStatus,
    Hypothesis,
    TestOutcome,
    TestSpec,
)


def _make_success_experiment(store, target_id="t1"):
    hyp = Hypothesis(
        target_id=target_id,
        statement="weakness exists",
        origin="strategy:auth-bypass",
    )
    store.save_hypothesis(hyp)
    return (
        hyp,
        Experiment(
            hypothesis_id=hyp.id,
            target_id=target_id,
            opensystem_version="0.1.0",
            test=TestSpec(name="t", parameters={"weakness": "auth-bypass"}),
            outcome=TestOutcome.SUCCESS,
            observed_result="confirmed",
        ),
    )


def test_finding_created_from_successful_experiment(store):
    hyp, exp = _make_success_experiment(store)
    engine = FindingEngine(store)
    finding = engine.create_from_experiment(exp, "t1")
    assert finding is not None
    assert finding.hypothesis_id == hyp.id
    assert finding.verification_status == FindingStatus.DISCOVERED
    assert finding.attack_hypothesis == hyp.statement


def test_no_finding_for_failed_experiment(store):
    hyp = Hypothesis(target_id="t1", statement="x", origin="strategy:auth-bypass")
    store.save_hypothesis(hyp)
    exp = Experiment(
        hypothesis_id=hyp.id,
        target_id="t1",
        opensystem_version="0.1.0",
        test=TestSpec(name="t", parameters={"weakness": "auth-bypass"}),
        outcome=TestOutcome.FAILURE,
    )
    engine = FindingEngine(store)
    assert engine.create_from_experiment(exp, "t1") is None


def test_finding_lifecycle_transitions(store):
    _, exp = _make_success_experiment(store)
    engine = FindingEngine(store)
    finding = engine.create_from_experiment(exp, "t1")

    engine.transition(finding.id, FindingStatus.CONFIRMED)
    engine.transition(finding.id, FindingStatus.DOCUMENTED)
    engine.transition(finding.id, FindingStatus.MITIGATION)
    engine.transition(finding.id, FindingStatus.VERIFICATION)
    engine.transition(finding.id, FindingStatus.CLOSED)

    closed = [f for f in engine.list_findings() if f.id == finding.id][0]
    assert closed.verification_status == FindingStatus.CLOSED


def test_invalid_finding_transition_raises(store):
    _, exp = _make_success_experiment(store)
    engine = FindingEngine(store)
    finding = engine.create_from_experiment(exp, "t1")

    with pytest.raises(ValueError):
        # DISCOVERED -> VERIFICATION is not allowed.
        engine.transition(finding.id, FindingStatus.VERIFICATION)


def test_closed_finding_remains_in_history(store):
    _, exp = _make_success_experiment(store)
    engine = FindingEngine(store)
    finding = engine.create_from_experiment(exp, "t1")
    engine.transition(finding.id, FindingStatus.CLOSED)

    # A solved vulnerability never disappears from the record.
    all_findings = engine.list_findings()
    assert any(f.id == finding.id for f in all_findings)
