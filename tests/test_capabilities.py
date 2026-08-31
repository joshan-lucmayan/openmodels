"""Tests for the explicit target-capability protocol.

An undeclared capability is "unsupported"; a declared-but-missing method is
an adapter contract violation that must raise; a runtime error inside a
capability method must propagate instead of looking like a missing
capability.
"""

from __future__ import annotations

import pytest

from opensystem.models import Target, TestOutcome, TestResult
from opensystem.target.interface import (
    AdapterCapabilityError,
    Capability,
    TargetAdapter,
    adapter_capability,
    adapter_supports,
)


class _MinimalAdapter(TargetAdapter):
    """Concrete adapter with no optional capabilities declared."""

    name = "minimal"

    def discover(self) -> Target:
        return Target(name="minimal")

    def observe(self):
        return []

    def describe(self) -> dict:
        return {}

    def execute_test(self, test):
        return TestResult(outcome=TestOutcome.INCONCLUSIVE)

    def collect_evidence(self):
        return []

    def reset(self) -> None:
        pass


class _BrokenDeclarationAdapter(_MinimalAdapter):
    """Declares TEST_PLANNING but never implements it — an adapter bug."""

    name = "broken-declaration"
    capabilities = frozenset({Capability.TEST_PLANNING})


class _RaisingAdapter(_MinimalAdapter):
    """Declares TEST_PLANNING and implements it badly — errors must surface."""

    name = "raising"
    capabilities = frozenset({Capability.TEST_PLANNING})

    def plan_test(self, hypothesis, target_model):
        raise RuntimeError("adapter implementation exploded")


def test_http_adapter_declares_real_capabilities(http_target):
    assert adapter_supports(http_target, Capability.DISCOVERY)
    assert adapter_supports(http_target, Capability.TEST_PLANNING)


def test_undeclared_capability_is_unsupported():
    adapter = _MinimalAdapter()
    assert not adapter_supports(adapter, Capability.TEST_PLANNING)
    assert adapter_capability(
        adapter, Capability.TEST_PLANNING, "plan_test"
    ) is None


def test_declared_but_missing_method_is_an_error():
    adapter = _BrokenDeclarationAdapter()
    with pytest.raises(AdapterCapabilityError):
        adapter_capability(
            adapter, Capability.TEST_PLANNING, "plan_test"
        )


def test_capability_runtime_error_propagates():
    adapter = _RaisingAdapter()
    plan = adapter_capability(
        adapter, Capability.TEST_PLANNING, "plan_test"
    )
    assert plan is not None
    with pytest.raises(RuntimeError, match="exploded"):
        plan(None, None)