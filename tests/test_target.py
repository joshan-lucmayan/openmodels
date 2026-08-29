"""Tests for the target abstraction and mock target lifecycle."""

from __future__ import annotations

from openmodels.models import TestOutcome, TestSpec


def test_discover_builds_target_model(mock_target):
    target = mock_target.discover()
    assert target.name == "mock-service"
    assert target.kind == "mock"
    assert target.adapter == "mock"
    assert len(target.assets) > 0


def test_discover_returns_stable_id(mock_target):
    t1 = mock_target.discover()
    t2 = mock_target.discover()
    assert t1.id == t2.id


def test_observe_returns_observations(mock_target):
    obs = mock_target.observe()
    assert len(obs) >= 5
    assert all(o.interface == "mock" for o in obs)


def test_describe_reports_weakness_state(mock_target):
    description = mock_target.describe()
    assert description["name"] == "mock-service"
    weaknesses = description["weaknesses"]
    assert "auth-bypass" in weaknesses
    assert weaknesses["auth-bypass"]["active"] is True


def test_execute_test_success_for_active_weakness(mock_target):
    result = mock_target.execute_test(
        TestSpec(name="t", parameters={"weakness": "auth-bypass"})
    )
    assert result.outcome == TestOutcome.SUCCESS


def test_execute_test_failure_after_defense(mock_target):
    assert mock_target.defend("auth-bypass") is True
    result = mock_target.execute_test(
        TestSpec(name="t", parameters={"weakness": "auth-bypass"})
    )
    assert result.outcome == TestOutcome.FAILURE


def test_execute_test_inconclusive_for_unknown_surface(mock_target):
    result = mock_target.execute_test(
        TestSpec(name="t", parameters={"weakness": "does-not-exist"})
    )
    assert result.outcome == TestOutcome.INCONCLUSIVE


def test_execute_test_error_for_missing_parameter(mock_target):
    result = mock_target.execute_test(TestSpec(name="t", parameters={}))
    assert result.outcome == TestOutcome.ERROR


def test_reset_restores_weaknesses(mock_target):
    mock_target.defend("auth-bypass")
    mock_target.reset()
    description = mock_target.describe()
    assert description["weaknesses"]["auth-bypass"]["active"] is True


def test_defend_returns_false_when_already_defended(mock_target):
    assert mock_target.defend("auth-bypass") is True
    assert mock_target.defend("auth-bypass") is False


def test_collect_evidence_after_test(mock_target):
    mock_target.execute_test(TestSpec(name="t", parameters={"weakness": "auth-bypass"}))
    evidence = mock_target.collect_evidence()
    assert len(evidence) == 1
    assert evidence[0].data["outcome"] == TestOutcome.SUCCESS.value
