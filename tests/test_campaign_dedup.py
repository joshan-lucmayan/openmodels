"""Tests for campaign finding deduplication and structured identities.

Identity rule: a finding for a violated boundary is identified by
(target, actor, resource, interface) — never by the human-readable
affected_component display string, which is presentation only.
"""

from __future__ import annotations

import pytest

from opensystem.campaign.engine import CampaignEngine
from opensystem.impact.engine import ImpactNotVerified, ImpactVerifier
from opensystem.models import Finding, FindingStatus
from opensystem.policy.models import Operation, Policy
from opensystem.proof.service import ProofKeyError, ProofSessionService


def _setup(store, mock_target, name="dedup"):
    target = mock_target.discover()
    engine = CampaignEngine(store)
    actors = list(mock_target.actors().values())
    resources = list(mock_target.resources().values())
    campaign = engine.create_campaign(
        name=name, target_adapter=mock_target, target=target,
        actors=actors, resources=resources,
    )
    engine.discover(campaign, mock_target, target)
    return engine, campaign, target


def test_campaign_rerun_does_not_duplicate_findings(store, mock_target):
    engine, campaign, target = _setup(store, mock_target)
    first = engine.run(campaign, mock_target, target)
    assert first.findings_created == 2

    # A repeated execution against the same unchanged boundaries must not
    # create another logically identical finding.
    fresh = CampaignEngine(store)
    resumed = fresh.resume(campaign.id)
    second = fresh.run(resumed, mock_target, target)
    assert second.findings_created == 0
    assert len(store.list_findings(target.id)) == 2


def test_closed_finding_does_not_suppress_new_violation(store, mock_target):
    """A CLOSED finding is history: a new violation creates a new finding."""
    engine, campaign, target = _setup(store, mock_target)
    engine.run(campaign, mock_target, target)
    for f in store.list_findings(target.id):
        store.update_finding_status(f.id, FindingStatus.CLOSED)

    fresh = CampaignEngine(store)
    resumed = fresh.resume(campaign.id)
    second = fresh.run(resumed, mock_target, target)
    assert second.findings_created == 2
    assert len(store.list_findings(target.id)) == 4


def test_findings_carry_structured_identity(store, mock_target):
    engine, campaign, target = _setup(store, mock_target)
    engine.run(campaign, mock_target, target)

    findings = store.list_findings(target.id)
    assert len(findings) == 2
    for f in findings:
        assert f.actor_id and f.resource_id and f.interface and f.objective_id
        assert f.interface == "stream_api"
        actor = store.get_actor(f.actor_id)
        resource = store.get_protected_resource(f.resource_id)
        assert actor is not None and resource is not None
        assert resource.name == "premium_model"
        # The finding is linked to a real objective of this campaign.
        objectives = {o.id for o in store.list_objectives(campaign.id)}
        assert f.objective_id in objectives


def test_boundary_identity_dedup_query(store, mock_target):
    target = mock_target.discover()
    actor = mock_target.actors()["free_user"]
    resource = mock_target.resources()["premium_model"]

    assert store.find_open_boundary_finding(
        target.id, actor.id, resource.id, "stream_api"
    ) is None

    finding = Finding(
        target_id=target.id,
        actor_id=actor.id,
        resource_id=resource.id,
        interface="stream_api",
    )
    store.save_finding(finding)

    assert store.find_open_boundary_finding(
        target.id, actor.id, resource.id, "stream_api"
    ) is not None
    # A different interface is a different boundary identity.
    assert store.find_open_boundary_finding(
        target.id, actor.id, resource.id, "chat_api"
    ) is None

    store.update_finding_status(finding.id, FindingStatus.CLOSED)
    assert store.find_open_boundary_finding(
        target.id, actor.id, resource.id, "stream_api"
    ) is None


def test_display_text_is_not_used_for_resolution(store, mock_target):
    """Tampering with the display string must not break the proof flow."""
    engine, campaign, target = _setup(store, mock_target)
    engine.run(campaign, mock_target, target)

    for f in store.list_findings(target.id):
        f.affected_component = "TAMPERED — display text no longer parseable"
        store.save_finding(f)

    finding = store.list_findings(target.id)[0]
    verification = ImpactVerifier(store).verify(finding, mock_target, target)
    assert verification.verified

    store.update_finding_status(finding.id, FindingStatus.CONFIRMED)
    finding.verification_status = FindingStatus.CONFIRMED
    policy = Policy(
        target_name="mock",
        allowed_operations=[
            Operation.OBSERVE, Operation.TEST, Operation.RESET,
            Operation.PROOF_SESSION,
        ],
    )
    service = ProofSessionService(store, policy=policy)
    result = service.create(finding, mock_target, target)
    assert result.raw_key.startswith("omk_")


def test_legacy_malformed_finding_is_not_verified_or_guessed(store, mock_target):
    """A finding without structured identity fails verification — no guessing
    from unparseable display strings."""
    target = mock_target.discover()
    store.save_target(target)
    finding = Finding(
        target_id=target.id,
        affected_component="junk display string",
    )
    store.save_finding(finding)

    with pytest.raises(ImpactNotVerified):
        ImpactVerifier(store).verify(finding, mock_target, target)

    records = store.get_impact_verifications(finding.id)
    assert len(records) == 1
    assert records[0].verified is False
    assert records[0].method == "finding-path-unresolvable"

    # Proof creation is refused via its own gate, not a parse crash.
    with pytest.raises(ProofKeyError):
        ProofSessionService(store).create(finding, mock_target, target)


def test_report_includes_campaign_boundary_tests(store, mock_target):
    """Campaign testing must be visible in the unified report without being
    counted as v0.1 experiments."""
    engine, campaign, target = _setup(store, mock_target)
    engine.run(campaign, mock_target, target)

    report = store.build_report(target.id)
    assert report.experiments_run == 0
    assert report.campaign_paths_tested == 10
    assert report.campaign_violations == 2
    assert report.findings_created == 2
