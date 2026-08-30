"""Tests for policy target scoping: name/adapter, environment, and scope.

Scoping fails closed: a policy that restricts environment or scope never
matches a target that does not declare the same value.
"""

from __future__ import annotations

import pytest

from opensystem.models import Target
from opensystem.policy.engine import PolicyEnforcer, PolicyViolation
from opensystem.policy.models import Operation, Policy


def _target(**updates) -> Target:
    values = {
        "name": "mock-service", "adapter": "mock",
        "environment": "local-mock", "scope": "test",
    }
    values.update(updates)
    return Target(**values)


def test_default_policy_applies_to_any_target():
    assert Policy().allows_target(_target())


def test_policy_matches_by_name_or_adapter():
    assert Policy(target_name="mock").allows_target(_target())
    assert Policy(target_name="mock-service").allows_target(_target())
    assert not Policy(target_name="other").allows_target(_target())


def test_policy_environment_restriction():
    policy = Policy(environment="local-mock")
    assert policy.allows_target(_target())

    production = Policy(environment="production")
    assert not production.allows_target(_target(environment=""))
    assert production.allows_target(_target(environment="production"))


def test_policy_scope_restriction_fails_closed():
    policy = Policy(scope="prod")
    assert not policy.allows_target(_target(scope="test"))
    # An undeclared target scope never matches a scoped policy.
    assert not policy.allows_target(_target(scope=""))
    assert policy.allows_target(_target(scope="prod"))


def test_enforcer_raises_for_out_of_scope_target():
    enforcer = PolicyEnforcer(Policy(environment="production"))
    with pytest.raises(PolicyViolation):
        enforcer.check(Operation.TEST, _target())


def test_enforcer_allows_matching_target():
    enforcer = PolicyEnforcer(
        Policy(target_name="mock", environment="local-mock", scope="test")
    )
    enforcer.check(Operation.TEST, _target())


def test_undeclared_capability_operation_denied_by_default():
    enforcer = PolicyEnforcer(Policy())
    with pytest.raises(PolicyViolation):
        enforcer.check(Operation.PROOF_SESSION, _target())
