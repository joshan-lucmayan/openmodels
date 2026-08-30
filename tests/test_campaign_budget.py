"""Tests for campaign budget enforcement (Policy.max_experiments).

The campaign budget counts every executed boundary test and must stop the
campaign cleanly, persisting everything tested so far.
"""

from __future__ import annotations

import pytest

from opensystem.campaign.engine import CampaignEngine
from opensystem.models import CampaignStatus, ObjectiveStatus
from opensystem.policy.engine import PolicyViolation
from opensystem.policy.models import Policy


def _setup(store, mock_target, **policy_fields):
    target = mock_target.discover()
    policy = Policy(**{"target_name": "mock", **policy_fields})
    engine = CampaignEngine(store, policy=policy)
    actors = list(mock_target.actors().values())
    resources = list(mock_target.resources().values())
    campaign = engine.create_campaign(
        name="budget", target_adapter=mock_target, target=target,
        actors=actors, resources=resources,
    )
    engine.discover(campaign, mock_target, target)
    return engine, campaign, target


def test_zero_budget_runs_nothing(store, mock_target):
    engine, campaign, target = _setup(store, mock_target, max_experiments=0)
    report = engine.run(campaign, mock_target, target)
    assert report.paths_tested == 0
    assert report.invariants_tested == 0
    assert report.findings_created == 0
    assert report.status == CampaignStatus.STOPPED
    assert report.stopped_reason == "POLICY_STOP"


def test_budget_of_one_tests_first_objective_then_stops(store, mock_target):
    engine, campaign, target = _setup(store, mock_target, max_experiments=1)
    report = engine.run(campaign, mock_target, target)
    # The first objective (guest -> premium_model) tests 3 interfaces; the
    # budget is then exhausted and the campaign stops cleanly.
    assert report.paths_tested == 3
    assert report.invariants_tested == 1
    assert report.status == CampaignStatus.STOPPED
    assert report.stopped_reason == "POLICY_STOP"


def test_budget_exhausted_mid_campaign(store, mock_target):
    engine, campaign, target = _setup(store, mock_target, max_experiments=4)
    report = engine.run(campaign, mock_target, target)
    # guest->premium (3 paths) + guest->admin_panel (1 path) = 4, then stop.
    assert report.paths_tested == 4
    assert report.invariants_tested == 2
    assert report.status == CampaignStatus.STOPPED


def test_stopped_state_is_persisted(store, mock_target):
    engine, campaign, target = _setup(store, mock_target, max_experiments=1)
    engine.run(campaign, mock_target, target)

    stored = store.get_campaign(campaign.id)
    assert stored.status == CampaignStatus.STOPPED
    assert stored.completed_at is not None

    objectives = store.list_objectives(campaign.id)
    tested = [o for o in objectives if o.status != ObjectiveStatus.FORMULATED]
    untested = [o for o in objectives if o.status == ObjectiveStatus.FORMULATED]
    assert len(tested) == 1
    assert len(untested) == len(objectives) - 1


def test_resumed_campaign_completes_under_fresh_budget(store, mock_target):
    engine, campaign, target = _setup(store, mock_target, max_experiments=1)
    first = engine.run(campaign, mock_target, target)
    assert first.status == CampaignStatus.STOPPED

    fresh = CampaignEngine(store)
    resumed = fresh.resume(campaign.id)
    second = fresh.run(resumed, mock_target, target)
    assert second.status == CampaignStatus.COMPLETED
    assert second.stopped_reason == ""


def test_policy_target_still_applies_during_campaign(store, mock_target):
    engine, campaign, target = _setup(
        store, mock_target, max_experiments=100, target_name="other-system"
    )
    with pytest.raises(PolicyViolation):
        engine.run(campaign, mock_target, target)
