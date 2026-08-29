"""Tests for the v0.2 security-boundary model in the mock target."""

from __future__ import annotations

from opensystem.models import (
    EntitlementDecision,
    ProtectedResourceType,
    TestOutcome,
    TestSpec,
)


def test_mock_has_actors_and_resources(mock_target):
    assert len(mock_target.actors()) == 4
    assert len(mock_target.resources()) == 3
    premium = mock_target.resources()["premium_model"]
    assert premium.resource_type == ProtectedResourceType.AI_MODEL


def test_mock_stable_ids_across_instances():
    from opensystem.target.mock import MockTarget

    a = MockTarget()
    b = MockTarget()
    assert a.discover().id == b.discover().id
    assert a.actors()["guest"].id == b.actors()["guest"].id
    assert a.resources()["premium_model"].id == b.resources()["premium_model"].id


def test_entitlement_decisions(mock_target):
    free = mock_target.actors()["free_user"]
    paid = mock_target.actors()["paid_user"]
    premium = mock_target.resources()["premium_model"]

    assert mock_target.entitlement_decision(free.id, premium.id) == EntitlementDecision.DENY
    assert mock_target.entitlement_decision(paid.id, premium.id) == EntitlementDecision.ALLOW


def test_boundary_crossed_on_unenforced_interface(mock_target):
    free = mock_target.actors()["free_user"]
    premium = mock_target.resources()["premium_model"]
    result = mock_target.execute_test(
        TestSpec(
            name="t",
            parameters={
                "actor": free.id,
                "interface": "stream_api",
                "resource": premium.id,
            },
        )
    )
    assert result.outcome == TestOutcome.SUCCESS
    assert "BOUNDARY CROSSED" in result.observed_result


def test_boundary_enforced_on_secure_interface(mock_target):
    free = mock_target.actors()["free_user"]
    premium = mock_target.resources()["premium_model"]
    result = mock_target.execute_test(
        TestSpec(
            name="t",
            parameters={
                "actor": free.id,
                "interface": "chat_api",
                "resource": premium.id,
            },
        )
    )
    assert result.outcome == TestOutcome.FAILURE


def test_legitimate_access_is_success(mock_target):
    paid = mock_target.actors()["paid_user"]
    premium = mock_target.resources()["premium_model"]
    result = mock_target.execute_test(
        TestSpec(
            name="t",
            parameters={
                "actor": paid.id,
                "interface": "stream_api",
                "resource": premium.id,
            },
        )
    )
    assert result.outcome == TestOutcome.SUCCESS
    assert "Legitimate" in result.observed_result


def test_enforce_patches_vulnerability(mock_target):
    free = mock_target.actors()["free_user"]
    premium = mock_target.resources()["premium_model"]

    assert mock_target.enforce("stream_api", "premium_model") is True
    result = mock_target.execute_test(
        TestSpec(
            name="t",
            parameters={
                "actor": free.id,
                "interface": "stream_api",
                "resource": premium.id,
            },
        )
    )
    assert result.outcome == TestOutcome.FAILURE


def test_unknown_actor_inconclusive(mock_target):
    premium = mock_target.resources()["premium_model"]
    result = mock_target.execute_test(
        TestSpec(
            name="t",
            parameters={
                "actor": "actor_nonexistent",
                "interface": "chat_api",
                "resource": premium.id,
            },
        )
    )
    assert result.outcome == TestOutcome.INCONCLUSIVE
