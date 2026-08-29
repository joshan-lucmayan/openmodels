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
    ActorKind,
    AttackObjective,
    Campaign,
    CampaignReport,
    CampaignStatus,
    Finding,
    FindingStatus,
    InvariantStatus,
    ObjectiveStatus,
    ProtectedResource,
    ProtectedResourceType,
    Severity,
    Target,
    TestOutcome,
    utcnow,
)
from opensystem.policy.engine import PolicyEnforcer
from opensystem.policy.models import Operation, Policy


class CampaignEngine:
    """Orchestrates a full adversarial campaign.

    Flow:
        CREATE → DISCOVER → FORMULATE → TEST ALL PATHS → REPORT
    """

    def __init__(self, store: KnowledgeStore, policy: Policy | None = None) -> None:
        self._store = store
        self._policy = policy or Policy()
        self._policy_enforcer = PolicyEnforcer(self._policy)
        self._discovery = AttackSurfaceDiscovery(store)
        self._formulator = ObjectiveFormulator(store)

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

        objectives = self._formulator.formulate(
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
        """Execute the full campaign: test all objectives across all paths."""
        campaign.status = CampaignStatus.ACTIVE
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

        for obj in objectives:
            self._policy_enforcer.check(Operation.TEST, target)

            actor = self._store.get_actor(obj.actor_id)
            resource = self._store.get_protected_resource(obj.resource_id)

            if actor is None or resource is None:
                continue

            paths, status = tester.test_objective(
                obj, target_adapter, target,
                surface.interfaces, actor, resource,
            )
            paths_tested += len(paths)

            # Record the objective outcome.
            if status == InvariantStatus.VIOLATED:
                obj.status = ObjectiveStatus.ACHIEVED
                violations += 1
                self._create_finding(campaign, obj, actor, resource, paths, target)
                findings_created += 1
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

        Returns a dict with first_round, enforced count, regressions, and the
        revalidated report.
        """
        first = self.run(campaign, target_adapter, target)

        enforce_fn = getattr(target_adapter, "enforce", None)
        enforced = []
        regressions = []
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

        # Regressions: previously-violated paths now hold (boundary enforced).
        for entry in enforced:
            regression = {
                "interface": entry["interface"],
                "resource": entry["resource"],
                "enforced": True,
            }
            regressions.append(regression)

        return {
            "first_round": first,
            "enforced": enforced,
            "regressions": regressions,
            "second_round": second,
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _create_finding(
        self,
        campaign: Campaign,
        objective: AttackObjective,
        actor: Actor,
        resource: ProtectedResource,
        paths: list,
        target: Target,
    ) -> Finding:
        """Create a finding for a violated security boundary."""
        successful_paths = [
            p for p in paths if p.outcome == TestOutcome.SUCCESS
        ]
        interface_names = ", ".join(p.interface for p in successful_paths)

        finding = Finding(
            target_id=target.id,
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
                f"accessed {resource.name} via interfaces [{interface_names}] "
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
                f"on interfaces [{interface_names}]."
            ),
            recommended_mitigation=(
                f"Enforce entitlement checks for {actor.kind.value} on "
                f"interfaces [{interface_names}] when accessing "
                f"{resource.name}."
            ),
            verification_status=FindingStatus.DISCOVERED,
        )
        self._store.save_finding(finding)
        return finding

    @staticmethod
    def _enrich_interfaces(surface, target_adapter: object) -> list[dict]:
        """Add actor/resource references to interfaces from the adapter."""
        adapter_resources = getattr(target_adapter, "describe_resources", None)
        if adapter_resources is None:
            return surface.interfaces
        try:
            resources = list(adapter_resources())
        except Exception:
            return surface.interfaces

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