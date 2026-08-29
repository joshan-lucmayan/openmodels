"""Tests for the policy/authorization boundary."""

from __future__ import annotations

import pytest

from opensystem.policy.engine import PolicyEnforcer, PolicyViolation
from opensystem.policy.models import Operation, Policy


def test_policy_allows_default_operations():
    policy = Policy(target_name="mock")
    enforcer = PolicyEnforcer(policy)
    # Default policy allows observe/test/reset.
    enforcer.check(Operation.OBSERVE)
    enforcer.check(Operation.TEST)
    enforcer.check(Operation.RESET)


def test_policy_blocks_disallowed_operation():
    policy = Policy(
        target_name="mock",
        allowed_operations=[Operation.OBSERVE],
    )
    enforcer = PolicyEnforcer(policy)
    with pytest.raises(PolicyViolation):
        enforcer.check(Operation.TEST)


def test_policy_blocks_destructive_by_default():
    policy = Policy(target_name="mock")
    enforcer = PolicyEnforcer(policy)
    with pytest.raises(PolicyViolation):
        enforcer.check(Operation.DESTRUCTIVE)


def test_policy_scoped_to_target():
    policy = Policy(target_name="mock")
    enforcer = PolicyEnforcer(policy)

    from opensystem.models import Target

    other = Target(name="production", adapter="webapp")
    with pytest.raises(PolicyViolation):
        enforcer.check(Operation.TEST, other)


def test_wildcard_policy_allows_any_target():
    policy = Policy(target_name="*")
    enforcer = PolicyEnforcer(policy)

    from opensystem.models import Target

    t = Target(name="production", adapter="webapp")
    enforcer.check(Operation.TEST, t)


def test_exhaustion_bounds():
    policy = Policy(max_rounds=5, max_experiments=10)
    enforcer = PolicyEnforcer(policy)
    assert not enforcer.is_exhausted(0, 0)
    assert enforcer.is_exhausted(5, 0)
    assert enforcer.is_exhausted(0, 10)
