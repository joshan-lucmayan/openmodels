"""Campaign engine — the v0.2 adversarial campaign orchestrator.

A campaign is a complete adversarial assessment against a target, centered
on the question:

    "Can an actor who is NOT entitled to a protected resource cause that
     resource to be accessed, consumed, modified, or disclosed?"

The campaign is resumable from the knowledge store.
"""

from __future__ import annotations

from opensystem import VERSION
from opensystem.campaign.discovery import AttackSurfaceDiscovery
from opensystem.campaign.objectives import InvariantTester, ObjectiveFormulator
from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Actor,
    AttackObjective,
    Campaign,
    CampaignReport,
    CampaignStatus,
    Finding,
    FindingStatus,
    InvariantStatus,
    ObjectiveStatus,
    ProtectedResource,
    Severity,
    Target,
    TestOutcome,
    utcnow,
)
from opensystem.policy.engine import PolicyEnforcer
from opensystem.policy.models import Operation, Policy, StopReason
from opensystem.target.interface import Capability, TargetAdapter, adapter_capability


class CampaignEngine:
    """Orchestrates a full adversarial campaign.

    Flow:
        CREATE → DISCOVER → FORMULATE → TEST ALL PATHS → REPORT

    The campaign budget (``Policy.max_experiments``) counts every executed
    boundary test and is enforced across all runs of the same engine —
    including the revalidation run inside ``enforce_and_revalidate``.
    """

    def __init__(self, store: KnowledgeStore, policy: Policy | None = None) -> None:
        self._store = store
        self._policy = policy or Policy()
        self._policy_enforcer = PolicyEnforcer(self._policy)
        self._discovery = AttackSurfaceDiscovery(store)
        self._formulator = ObjectiveFormulator(store)
        self._experiments_used = 0

    # ------------------------------------------------------------------ #
    # Campaign lifecycle
    # ------------------------------------------------------------------ #

    def create_campaign(
        self,
        name: str,
        target_adapter: object,
        target: Target,
        description: str = "",
        actors: list[Actor] | None = None,
        resources: list[ProtectedResource] | None = None,
    ) -> Campaign:
        """Create a new campaign and persist its target, actors, resources."""
        target.adapter = getattr(target_adapter, "name", target.adapter)
        self._store.save_target(target)

        campaign = Campaign(
            name=name,
            target_id=target.id,
            target_adapter=target.adapter,
            description=description or f"Campaign against {target.name}",
            status=CampaignStatus.CREATED,
        )

        actors = actors or []
        resources = resources or []

        for a in actors:
            self._store.save_actor(a)
            campaign.actor_ids.append(a.id)
        for r in resources:
            self._store.save_protected_resource(r)
            campaign.resource_ids.append(r.id)

        self._store.save_campaign(campaign)
        return campaign

    def discover(self, campaign: Campaign, target_adapter: object, target: Target) -> None:
        """Discover the attack surface and formulate objectives."""
        campaign.status = CampaignStatus.DISCOVERING
        self._store.save_campaign(campaign)

        surface = self._discovery.discover(target_adapter, target)

        actors = [
            self._store.get_actor(aid) for aid in campaign.actor_ids
            if self._store.get_actor(aid) is not None
        ]
        resources = [
            self._store.get_protected_resource(rid) for rid in campaign.resource_ids
            if self._store.get_protected_resource(rid) is not None
        ]

        self._formulator.formulate(
            campaign, target, target_adapter, actors, resources
        )

        surface.interfaces = self._enrich_interfaces(surface, target_adapter)
        self._store.save_attack_surface(surface)

    def run(
        self,
        campaign: Campaign,
        target_adapter: object,
        target: Target,
    ) -> CampaignReport:
        """Execute the campaign: test all objectives across all paths.

        The policy budget (max_experiments) is checked before each objective;
        when it is exhausted the campaign stops cleanly with status STOPPED,
        persisting everything tested so far. A stopped campaign can be
        resumed with a fresh engine or a raised budget.
        """
        campaign.status = CampaignStatus.ACTIVE
        if campaign.started_at is None:
            campaign.started_at = utcnow()
        self._store.save_campaign(campaign)

        surface = self._store.get_attack_surface(target.id)
        if surface is None:
            raise RuntimeError(
                "No attack surface found. Call discover() before run()."
            )

        objectives = self._store.list_objectives(campaign.id)
        tester = InvariantTester(self._store)

        violations = 0
        passes = 0
        inconcl = 0
        findings_created = 0
        paths_tested = 0
        stopped_reason = ""

        for obj in objectives:
            if self._policy_enforcer.experiments_remaining(
                self._experiments_used
            ) <= 0:
                stopped_reason = StopReason.POLICY_STOP.value
                break

            self._policy_enforcer.check(Operation.TEST, target)

            actor = self._store.get_actor(obj.actor_id)
            resource = self._store.get_protected_resource(obj.resource_id)

            if actor is None or resource is None:
                continue

            paths, status = tester.test_objective(
                obj, target_adapter, target,
                surface.interfaces, actor, resource,
                campaign_id=campaign.id,
            )
            paths_tested += len(paths)
            self._experiments_used += len(paths)

            # Record the objective outcome.
            if status == InvariantStatus.VIOLATED:
                obj.status = ObjectiveStatus.ACHIEVED
                violations += 1
                created = self._create_findings(
                    campaign, obj, actor, resource, paths, target
                )
                findings_created += len(created)
            elif status == InvariantStatus.PASSED:
                obj.status = ObjectiveStatus.BLOCKED
                passes += 1
            else:
                obj.status = ObjectiveStatus.INCONCLUSIVE
                inconcl += 1

            self._store.update_objective_status(obj.id, obj.status)
            self._store.update_invariant_status(
                obj.security_invariant_id, status
            )

        if stopped_reason:
            campaign.status = CampaignStatus.STOPPED
        else:
            campaign.status = CampaignStatus.COMPLETED
        campaign.completed_at = utcnow()
        self._store.save_campaign(campaign)

        return CampaignReport(
            campaign_id=campaign.id,
            target_id=target.id,
            opensystem_version=VERSION,
            status=campaign.status,
            actors=len(campaign.actor_ids),
            protected_resources=len(campaign.resource_ids),
            objectives_formulated=len(objectives),
            objectives_achieved=violations,
            invariants_tested=violations + passes + inconcl,
            invariants_passed=passes,
            invariants_violated=violations,
            paths_tested=paths_tested,
            findings_created=findings_created,
            open_findings=findings_created,
            stopped_reason=stopped_reason,
        )

    def resume(self, campaign_id: str) -> Campaign | None:
        """Resume a previously-created campaign from the store."""
        return self._store.get_campaign(campaign_id)

    def enforce_and_revalidate(
        self,
        campaign: Campaign,
        target_adapter: object,
        target: Target,
    ) -> dict:
        """The adversarial improvement cycle (v0.2).

        Flow:
            campaign run → violations found
            defender enforces the violated boundaries (via adapter.enforce)
            revalidate → the previously-violated boundary now holds
            (regression), and any remaining violations are re-examined.

        Returns a dict with first_round, enforced boundaries, and the
        revalidated report.
        """
        first = self.run(campaign, target_adapter, target)

        enforce_fn = adapter_capability(
            target_adapter, Capability.ENFORCEMENT, "enforce"
        )
        enforced: list[dict] = []
        if enforce_fn is not None:
            for actor_id in campaign.actor_ids:
                for path in self._store.list_attack_paths(
                    actor_ids=[actor_id], outcome=TestOutcome.SUCCESS
                ):
                    interface = path.interface
                    resource = path.resource_id
                    res = self._store.get_protected_resource(resource)
                    if res is None:
                        continue
                    if enforce_fn(interface, res.name):
                        enforced.append(
                            {"interface": interface, "resource": res.name}
                        )

        second = self.run(campaign, target_adapter, target)

        return {
            "first_round": first,
            "enforced": enforced,
            "second_round": second,
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _create_findings(
        self,
        campaign: Campaign,
        objective: AttackObjective,
        actor: Actor,
        resource: ProtectedResource,
        paths: list,
        target: Target,
    ) -> list[Finding]:
        """Create findings for a violated security boundary.

        One finding per violated (actor, resource, interface) identity. A
        repeated campaign run against the same unchanged boundary reuses the
        existing open finding instead of duplicating it; a CLOSED finding for
        the same identity does not suppress a new violation (the boundary may
        have regressed).
        """
        created: list[Finding] = []
        successful_paths = [
            p for p in paths if p.outcome == TestOutcome.SUCCESS
        ]

        for path in successful_paths:
            interface_names = path.interface
            existing = self._store.find_open_boundary_finding(
                target.id, actor.id, resource.id, path.interface
            )
            if existing is not None:
                continue

            finding = Finding(
                target_id=target.id,
                objective_id=objective.id,
                actor_id=actor.id,
                resource_id=resource.id,
                interface=path.interface,
                severity=Severity.HIGH,
                affected_component=(
                    f"actor={actor.kind.value}/{actor.name} → "
                    f"interface=[{interface_names}] → "
                    f"resource={resource.name}"
                ),
                attack_hypothesis=(
                    f"{actor.name} ({actor.kind.value}) can access "
                    f"{resource.name} without entitlement"
                ),
                observed_behavior=(
                    f"Security boundary not enforced: {actor.name} successfully "
                    f"accessed {resource.name} via interface {interface_names} "
                    f"despite lacking entitlement."
                ),
                impact=(
                    f"Unauthorized actor {actor.name} ({actor.kind.value}) "
                    f"gained access to protected resource {resource.name} "
                    f"({resource.resource_type.value})."
                ),
                reproduction=(
                    f"Run campaign {campaign.id}, objective {objective.id}. "
                    f"Test actor={actor.id} against resource={resource.id} "
                    f"on interface [{interface_names}]."
                ),
                recommended_mitigation=(
                    f"Enforce entitlement checks for {actor.kind.value} on "
                    f"interface {interface_names} when accessing "
                    f"{resource.name}."
                ),
                verification_status=FindingStatus.DISCOVERED,
            )
            self._store.save_finding(finding)
            created.append(finding)
        return created

    @staticmethod
    def _enrich_interfaces(
        surface: object, target_adapter: TargetAdapter
    ) -> list[dict]:
        """Add actor/resource references to interfaces from the adapter."""
        adapter_resources = adapter_capability(
            target_adapter, Capability.DISCOVERY, "describe_resources"
        )
        if adapter_resources is None:
            return surface.interfaces

        resources = list(adapter_resources())
        resource_map = {r.get("name", r.get("id")): r for r in resources}
        enriched = []
        for iface in surface.interfaces:
            name = iface.get("name", "")
            exposed = [
                rname for rname, rd in resource_map.items()
                if name in rd.get("interfaces", [])
            ]
            enriched.append({**iface, "exposes": exposed})
        return enriched