"""Tests for the explicit target-capability protocol.

An undeclared capability is "unsupported"; a declared-but-missing method is
an adapter contract violation that must raise; a runtime error inside a
capability method must propagate instead of looking like a missing
capability.
"""

from __future__ import annotations

import pytest

from opensystem.impact.engine import ImpactNotVerified, ImpactVerifier
from opensystem.models import Finding, Target, TestOutcome, TestResult
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
    """Declares ENTITLEMENT but never implements it — an adapter bug."""

    name = "broken-declaration"
    capabilities = frozenset({Capability.ENTITLEMENT})


class _RaisingAdapter(_MinimalAdapter):
    """Declares ENTITLEMENT and implements it badly — errors must surface."""

    name = "raising"
    capabilities = frozenset({Capability.ENTITLEMENT})

    def entitlement_decision(self, actor_id, resource_id, action="access"):
        raise RuntimeError("adapter implementation exploded")


def test_mock_declares_all_capabilities(mock_target):
    for capability in Capability:
        assert adapter_supports(mock_target, capability)


def test_undeclared_capability_is_unsupported():
    adapter = _MinimalAdapter()
    assert not adapter_supports(adapter, Capability.ENTITLEMENT)
    assert adapter_capability(
        adapter, Capability.ENTITLEMENT, "entitlement_decision"
    ) is None


def test_declared_but_missing_method_is_an_error():
    adapter = _BrokenDeclarationAdapter()
    with pytest.raises(AdapterCapabilityError):
        adapter_capability(
            adapter, Capability.ENTITLEMENT, "entitlement_decision"
        )


def test_capability_runtime_error_propagates():
    adapter = _RaisingAdapter()
    decision = adapter_capability(
        adapter, Capability.ENTITLEMENT, "entitlement_decision"
    )
    assert decision is not None
    with pytest.raises(RuntimeError, match="exploded"):
        decision("a", "b")


def test_impact_verifier_reports_unsupported_adapter(store):
    target = _MinimalAdapter().discover()
    store.save_target(target)
    finding = Finding(target_id=target.id, actor_id="a", resource_id="r",
                      interface="i")
    store.save_finding(finding)

    with pytest.raises(ImpactNotVerified):
        ImpactVerifier(store).verify(finding, _MinimalAdapter(), target)

    records = store.get_impact_verifications(finding.id)
    assert records[0].method == "adapter-does-not-support-impact-probe"


def test_discovery_without_capability_falls_back_to_target_interfaces(store):
    from opensystem.campaign.discovery import AttackSurfaceDiscovery

    adapter = _MinimalAdapter()
    target = adapter.discover()
    target.interfaces = ["iface_a", "iface_b"]
    surface = AttackSurfaceDiscovery(store).discover(adapter, target)
    assert [i["name"] for i in surface.interfaces] == ["iface_a", "iface_b"]
    assert surface.resources == []


def test_mock_behavior_preserved(mock_target):
    """The mock still answers entitlements and proof-session support."""
    assert adapter_capability(
        mock_target, Capability.ENTITLEMENT, "entitlement_decision"
    ) is not None
    assert adapter_supports(mock_target, Capability.PROOF_SESSION)
