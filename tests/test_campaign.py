"""Tests for the campaign engine (v0.2)."""

from __future__ import annotations

import pytest

from openmodels.campaign.engine import CampaignEngine
from openmodels.campaign.discovery import AttackSurfaceDiscovery
from openmodels.campaign.objectives import InvariantTester, ObjectiveFormulator
from openmodels.models import (
    AttackObjective,
    CampaignStatus,
    EntitlementDecision,
    InvariantStatus,
    ObjectiveStatus,
    TestOutcome,
)


def _setup_campaign(store, mock_target):
    target = mock_target.discover()
    engine = CampaignEngine(store)
    actors = list(mock_target.actors().values())
    resources = list(mock_target.resources().values())
    campaign = engine.create_campaign(
        name="test-campaign",
        target_adapter=mock_target,
        target=target,
        actors=actors,
        resources=resources,
    )
    engine.discover(campaign, mock_target, target)
    return engine, campaign, target


def test_campaign_creation(store, mock_target):
    engine, campaign, _ = _setup_campaign(store, mock_target)
    assert campaign.status == CampaignStatus.DISCOVERING
    assert len(campaign.actor_ids) == 4
    assert len(campaign.resource_ids) == 3


def test_campaign_discovery_builds_surface(store, mock_target):
    _, campaign, _ = _setup_campaign(store, mock_target)
    surface = store.get_attack_surface(campaign.target_id)
    assert surface is not None
    assert len(surface.interfaces) == 5
    assert len(surface.resources) == 3


def test_objective_formulation_only_denied_pairs(store, mock_target):
    target = mock_target.discover()
    engine = CampaignEngine(store)
    actors = list(mock_target.actors().values())
    resources = list(mock_target.resources().values())
    campaign = engine.create_campaign(
        name="c", target_adapter=mock_target, target=target,
        actors=actors, resources=resources,
    )
    formulator = ObjectiveFormulator(store)
    objectives = formulator.formulate(
        campaign, target, mock_target, actors, resources
    )
    # 4 actors x 3 resources = 12; 6 are ALLOW -> 6 DENY objectives.
    assert len(objectives) == 6
    # paid_user -> premium_model is ALLOW -> no objective.
    paid = mock_target.actors()["paid_user"]
    premium = mock_target.resources()["premium_model"]
    assert all(
        o.actor_id != paid.id or o.resource_id != premium.id
        for o in objectives
    )


def test_invariant_tester_detects_violation(store, mock_target):
    target = mock_target.discover()
    free = mock_target.actors()["free_user"]
    premium = mock_target.resources()["premium_model"]
    surface = store.get_attack_surface(target.id) or AttackSurfaceDiscovery(store).discover(mock_target, target)

    from openmodels.models import SecurityInvariant

    invariant = SecurityInvariant(actor_id=free.id, resource_id=premium.id)
    store.save_invariant(invariant)
    objective = AttackObjective(
        campaign_id="c",
        actor_id=free.id,
        resource_id=premium.id,
        security_invariant_id=invariant.id,
    )
    tester = InvariantTester(store)
    paths, status = tester.test_objective(
        objective, mock_target, target, surface.interfaces, free, premium
    )
    assert status == InvariantStatus.VIOLATED
    assert any(p.outcome == TestOutcome.SUCCESS for p in paths)
    # Violated via stream_api only.
    successful = [p.interface for p in paths if p.outcome == TestOutcome.SUCCESS]
    assert successful == ["stream_api"]


def test_invariant_tester_passes_secure_boundary(store, mock_target):
    target = mock_target.discover()
    free = mock_target.actors()["free_user"]
    admin_panel = mock_target.resources()["admin_panel"]
    surface = store.get_attack_surface(target.id) or AttackSurfaceDiscovery(store).discover(mock_target, target)

    from openmodels.models import SecurityInvariant

    invariant = SecurityInvariant(actor_id=free.id, resource_id=admin_panel.id)
    store.save_invariant(invariant)
    objective = AttackObjective(
        campaign_id="c",
        actor_id=free.id,
        resource_id=admin_panel.id,
        security_invariant_id=invariant.id,
    )
    tester = InvariantTester(store)
    paths, status = tester.test_objective(
        objective, mock_target, target, surface.interfaces, free, admin_panel
    )
    assert status == InvariantStatus.PASSED
    assert all(p.outcome == TestOutcome.FAILURE for p in paths)


def test_full_campaign_run(store, mock_target):
    engine, campaign, target = _setup_campaign(store, mock_target)
    report = engine.run(campaign, mock_target, target)

    assert report.status == CampaignStatus.COMPLETED
    assert report.objectives_formulated == 6
    # premium_model boundary crossed on stream_api by guest and free_user.
    assert report.invariants_violated == 2
    assert report.invariants_passed == 4
    assert report.findings_created == 2

    # The violated objective statuses are recorded.
    objectives = store.list_objectives(campaign.id)
    achieved = [o for o in objectives if o.status == ObjectiveStatus.ACHIEVED]
    blocked = [o for o in objectives if o.status == ObjectiveStatus.BLOCKED]
    assert len(achieved) == 2
    assert len(blocked) == 4


def test_findings_reference_violated_paths(store, mock_target):
    engine, campaign, target = _setup_campaign(store, mock_target)
    engine.run(campaign, mock_target, target)

    findings = store.list_findings()
    assert len(findings) == 2
    for f in findings:
        assert "stream_api" in f.affected_component
        assert "premium_model" in f.affected_component
        assert "without entitlement" in f.attack_hypothesis
