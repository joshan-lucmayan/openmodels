"""A deterministic mock target demonstrating the adversarial lifecycle.

The mock target is intentionally simple and deterministic. It models a system
as a set of weaknesses (v0.1 weakness model) AND as a set of protected
resources, actors, and entitlement boundaries (v0.2 security-boundary model).

Design intent
-------------
- It is a REAL implementation of the TargetAdapter contract.
- It is NOT an autonomous attacker; it is a controllable stand-in so the core
  engine can be developed and tested before connecting real targets.
- `defend()` (v0.1) and `enforce()` (v0.2) simulate the defender patching
  weaknesses / enforcing boundaries, enabling learning-from-failure and
  evolution demonstrations.
"""

from __future__ import annotations

from pydantic import BaseModel

from opensystem.models import (
    Actor,
    ActorKind,
    EntitlementDecision,
    Evidence,
    EvidenceKind,
    Observation,
    ProtectedResource,
    ProtectedResourceType,
    Severity,
    Target,
    TestOutcome,
    TestResult,
    TestSpec,
    utcnow,
)
from opensystem.target.interface import TargetAdapter


class Weakness(BaseModel):
    """A known weakness in the mock target (v0.1 weakness model)."""

    key: str
    name: str
    component: str
    severity: Severity = Severity.MEDIUM
    description: str = ""
    active: bool = True
    block_message: str = "Request rejected by enforcement layer."
    success_message: str = "Weakness confirmed."
    defend_note: str = ""


class MockTarget(TargetAdapter):
    """Deterministic target with weaknesses and security boundaries.

    Test protocols
    --------------
    1. Weakness model (v0.1): parameters with a ``weakness`` key.
         SUCCESS     if the weakness is active
         FAILURE     if the weakness is blocked by a defense
         INCONCLUSIVE if the named weakness does not exist

    2. Security-boundary model (v0.2): parameters with ``actor``, ``interface``,
       and ``resource`` keys.
         SUCCESS     if the actor accessed the resource without entitlement
                     (boundary crossed — OR legitimate entitled access)
         FAILURE     if the boundary was enforced (access denied)
         ERROR       malformed parameters

    The boundary model reflects the core adversarial question: can an actor who
    is NOT entitled to a protected resource cause that resource to be accessed?
    """

    name = "mock"

    def __init__(self, name: str = "mock-service", version: str = "0.2.0"):
        self.target_name = name
        self.target_version = version
        self._target_id: str | None = None

        # v0.1 weakness model
        self._weaknesses: dict[str, Weakness] = {}
        self._observations: list[Observation] = []
        self._seed_weaknesses()
        self._observe_initial()

        # v0.2 security-boundary model
        self._resources: dict[str, ProtectedResource] = {}
        self._actors: dict[str, Actor] = {}
        self._entitlement: dict[tuple, EntitlementDecision] = {}
        self._enforcement: dict[tuple, bool] = {}
        self._last_result: TestResult | None = None
        self._seed_boundaries()

    # ------------------------------------------------------------------ #
    # v0.1 — Weakness model
    # ------------------------------------------------------------------ #

    def _seed_weaknesses(self) -> None:
        seeds = [
            Weakness(
                key="auth-bypass",
                name="authentication bypass via default credential",
                component="auth",
                severity=Severity.CRITICAL,
                success_message="Default admin credential accepted.",
                block_message="Authentication layer rejected the default credential.",
                defend_note="Rotated default credential and enforced credential policy.",
            ),
            Weakness(
                key="authz-ownership",
                name="horizontal privilege escalation on object ownership",
                component="authz",
                severity=Severity.HIGH,
                success_message="Read another principal's object without authorization.",
                block_message="Central authorization layer rejected cross-principal access.",
                defend_note="Added central ownership checks at the authorization layer.",
            ),
            Weakness(
                key="input-traversal",
                name="path traversal in file retrieval endpoint",
                component="storage",
                severity=Severity.HIGH,
                success_message="Retrieved file outside the data directory.",
                block_message="Path canonicalization rejected the traversal.",
                defend_note="Canonicalize and constrain paths before access.",
            ),
            Weakness(
                key="resource-abuse",
                name="unbounded resource consumption on pagination",
                component="api",
                severity=Severity.MEDIUM,
                success_message="Triggered unbounded pagination scan.",
                block_message="Rate and size limits rejected the oversized request.",
                defend_note="Enforced pagination and rate limits.",
            ),
            Weakness(
                key="agent-tool-boundary",
                name="agent tool boundary escape",
                component="agent",
                severity=Severity.HIGH,
                success_message="Invoked a tool outside the agent's granted set.",
                block_message="Tool boundary enforcement rejected the invocation.",
                defend_note="Constrained the agent tool router to the granted tool set.",
            ),
            Weakness(
                key="session-fixation",
                name="session fixation via unvalidated session id",
                component="session",
                severity=Severity.MEDIUM,
                success_message="Fixed a session id accepted post-authentication.",
                block_message="Session layer re-issued the session id.",
                defend_note="Re-issue session ids on authentication.",
            ),
            Weakness(
                key="state-transition",
                name="illegal state transition in workflow",
                component="workflow",
                severity=Severity.MEDIUM,
                success_message="Performed an illegal workflow state transition.",
                block_message="Workflow engine rejected the illegal transition.",
                defend_note="Enforce the allowed state-transition table.",
            ),
            Weakness(
                key="dependency-supply-chain",
                name="unpinned transitive dependency",
                component="dependencies",
                severity=Severity.HIGH,
                success_message="Resolved an untrusted version of the dependency.",
                block_message="Dependency resolution pinned to a verified version.",
                defend_note="Pin and verify all transitive dependencies.",
            ),
        ]
        self._weaknesses = {w.key: w for w in seeds}

    def _observe_initial(self) -> None:
        for w in self._weaknesses.values():
            self._observations.append(
                Observation(
                    target_id=self.target_name,
                    interface="mock",
                    data={
                        "component": w.component,
                        "weakness_key": w.key,
                        "active": w.active,
                        "name": w.name,
                    },
                    source="mock.discover",
                )
            )

    # ------------------------------------------------------------------ #
    # v0.2 — Security-boundary model
    # ------------------------------------------------------------------ #

    def _seed_boundaries(self) -> None:
        # Protected resources. Their auto-generated IDs become the canonical
        # keys used by the entitlement and enforcement matrices.
        self._resources = {
            "premium_model": ProtectedResource(
                name="premium_model",
                resource_type=ProtectedResourceType.AI_MODEL,
                value="premium AI inference",
                description="Premium-tier AI inference capability.",
                interfaces=["chat_api", "stream_api", "job_api"],
            ),
            "admin_panel": ProtectedResource(
                name="admin_panel",
                resource_type=ProtectedResourceType.WEB_UI,
                value="administrative console",
                description="Administrative console for the platform.",
                interfaces=["admin_console"],
            ),
            "user_data": ProtectedResource(
                name="user_data",
                resource_type=ProtectedResourceType.DATA,
                value="user private data",
                description="Authenticated users' private data.",
                interfaces=["user_api"],
            ),
        }

        # Actors. Privileges are declared here and may differ from reality —
        # OpenSystem investigates whether the target actually enforces them.
        self._actors = {
            "guest": Actor(
                name="guest",
                kind=ActorKind.UNAUTHENTICATED,
                description="Anonymous visitor, no account.",
                entitlements=[],
            ),
            "free_user": Actor(
                name="free_user",
                kind=ActorKind.FREE_USER,
                description="Free-tier user; entitled only to the basic model.",
                entitlements=["basic_model"],
            ),
            "paid_user": Actor(
                name="paid_user",
                kind=ActorKind.PAID_USER,
                description="Paid-tier user; entitled to premium inference.",
                entitlements=["basic_model", "premium_model"],
            ),
            "org_admin": Actor(
                name="org_admin",
                kind=ActorKind.ORG_ADMIN,
                description="Organization administrator.",
                entitlements=[
                    "basic_model", "premium_model",
                    "admin_panel", "user_data",
                ],
            ),
        }

        # Key every matrix by canonical ID (not name).
        self._entitlement = {
            ("paid_user", "premium_model"): EntitlementDecision.ALLOW,
            ("org_admin", "premium_model"): EntitlementDecision.ALLOW,
            ("org_admin", "admin_panel"): EntitlementDecision.ALLOW,
            ("free_user", "user_data"): EntitlementDecision.ALLOW,
            ("paid_user", "user_data"): EntitlementDecision.ALLOW,
            ("org_admin", "user_data"): EntitlementDecision.ALLOW,
        }

        # Enforcement matrix: does interface X actually enforce the boundary
        # protecting resource Y? Default is enforced (secure). A "False" here
        # is a real vulnerability — the security boundary is NOT enforced.
        self._enforcement = {
            ("chat_api", "premium_model"): True,
            ("stream_api", "premium_model"): False,  # <-- VULNERABILITY
            ("job_api", "premium_model"): True,
            ("admin_console", "admin_panel"): True,
            ("user_api", "user_data"): True,
        }

        # Assign STABLE, name-derived IDs so the mock is deterministic across
        # instantiations (a campaign created in one process can be resumed in
        # another). Real adapters would issue stable IDs too.
        for key, actor in self._actors.items():
            actor.id = f"actor_{key}"
        for key, resource in self._resources.items():
            resource.id = f"res_{key}"

    def _id_for_actor(self, key: str) -> str:
        return self._actors[key].id

    def _id_for_resource(self, key: str) -> str:
        return self._resources[key].id

    def _resolve(self, value: str, mapping: dict) -> object | None:
        """Resolve a value that may be an ID or a name to the stored model."""
        if value in mapping:
            return mapping[value]
        for model in mapping.values():
            if model.id == value:
                return model
        return None

    # ------------------------------------------------------------------ #
    # TargetAdapter contract
    # ------------------------------------------------------------------ #

    def discover(self) -> Target:
        if self._target_id is None:
            # Stable, name-derived target ID so campaigns remain resumable
            # across processes.
            self._target_id = f"target_{self.target_name}"
        return Target(
            id=self._target_id,
            name=self.target_name,
            kind="mock",
            adapter=self.name,
            version=self.target_version,
            description=(
                "Deterministic mock system with seeded weaknesses and "
                "security boundaries, used to exercise the adversarial engine."
            ),
            assets=[w.key for w in self._weaknesses.values()],
            interfaces=[
                "chat_api", "stream_api", "job_api",
                "admin_console", "user_api",
            ],
            trust_boundaries=["internal"],
        )

    def observe(self) -> list[Observation]:
        return list(self._observations)

    def describe(self) -> dict:
        return {
            "name": self.target_name,
            "adapter": self.name,
            "version": self.target_version,
            "weaknesses": {
                k: {
                    "name": w.name,
                    "component": w.component,
                    "severity": w.severity.value,
                    "active": w.active,
                    "defended": not w.active,
                }
                for k, w in self._weaknesses.items()
            },
            "protected_resources": list(self._resources),
            "actors": list(self._actors),
        }

    def execute_test(self, test: TestSpec) -> TestResult:
        params = test.parameters or {}
        if "weakness" in params:
            return self._execute_weakness_test(params)
        if all(k in params for k in ("actor", "interface", "resource")):
            return self._execute_boundary_test(params)
        return TestResult(
            outcome=TestOutcome.ERROR,
            observed_result="Test parameters must specify 'weakness' or "
                            "'actor' + 'interface' + 'resource'.",
            detail={"error": "malformed-test"},
        )

    def _execute_weakness_test(self, params: dict) -> TestResult:
        weakness_key = params.get("weakness")
        weakness = self._weaknesses.get(weakness_key)
        if weakness is None:
            result = TestResult(
                outcome=TestOutcome.INCONCLUSIVE,
                observed_result=(
                    f"No such weakness '{weakness_key}' — target does not "
                    "expose that attack surface."
                ),
                detail={"weakness": weakness_key, "reason": "unknown-surface"},
            )
        elif weakness.active:
            result = TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=weakness.success_message,
                detail={
                    "weakness": weakness_key,
                    "component": weakness.component,
                    "name": weakness.name,
                },
            )
        else:
            result = TestResult(
                outcome=TestOutcome.FAILURE,
                observed_result=weakness.block_message,
                detail={
                    "weakness": weakness_key,
                    "component": weakness.component,
                    "defense": weakness.defend_note,
                },
            )
        self._last_result = result
        return result

    def _execute_boundary_test(self, params: dict) -> TestResult:
        """Test whether an actor can cross a security boundary.

        The decision is based on the declared entitlement, but enforcement is
        determined per-interface. If the actor is NOT entitled and the
        interface does NOT enforce the boundary, the actor successfully
        crosses it — a finding.
        """
        actor = self._resolve(params["actor"], self._actors)
        interface = params["interface"]
        resource = self._resolve(params["resource"], self._resources)

        if actor is None:
            result = TestResult(
                outcome=TestOutcome.INCONCLUSIVE,
                observed_result=f"Unknown actor '{params['actor']}'.",
                detail={"actor": params["actor"], "reason": "unknown-actor"},
            )
            self._last_result = result
            return result
        if resource is None:
            result = TestResult(
                outcome=TestOutcome.INCONCLUSIVE,
                observed_result=f"Unknown resource '{params['resource']}'.",
                detail={"resource": params["resource"], "reason": "unknown-resource"},
            )
            self._last_result = result
            return result

        decision = self._entitlement.get(
            (actor.name, resource.name), EntitlementDecision.DENY
        )
        enforced = self._enforcement.get((interface, resource.name), True)

        if decision == EntitlementDecision.ALLOW:
            # Entitled access — legitimate, not a boundary crossing.
            result = TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    f"Legitimate access: {actor.name} is entitled to "
                    f"{resource.name}."
                ),
                detail={
                    "actor": actor.name, "interface": interface,
                    "resource": resource.name, "decision": "ALLOW",
                },
            )
        elif enforced:
            result = TestResult(
                outcome=TestOutcome.FAILURE,
                observed_result=(
                    f"Boundary enforced: {actor.name} denied access to "
                    f"{resource.name} via {interface} (no entitlement)."
                ),
                detail={
                    "actor": actor.name, "interface": interface,
                    "resource": resource.name, "decision": "DENY",
                    "enforced": True,
                },
            )
        else:
            result = TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    f"BOUNDARY CROSSED: {actor.name} accessed {resource.name} "
                    f"via {interface} despite having no entitlement."
                ),
                detail={
                    "actor": actor.name, "interface": interface,
                    "resource": resource.name, "decision": "DENY",
                    "enforced": False,
                },
            )
        self._last_result = result
        return result

    def collect_evidence(self) -> list[Evidence]:
        if self._last_result is None:
            return []
        result = self._last_result
        return [
            Evidence(
                kind=EvidenceKind.OBSERVATION,
                data={
                    "outcome": result.outcome.value,
                    "observed_result": result.observed_result,
                    "detail": result.detail,
                },
                reference="mock.collect_evidence",
            )
        ]

    def reset(self) -> None:
        self._last_result = None
        for w in self._weaknesses.values():
            w.active = True
        for key in list(self._enforcement):
            self._enforcement[key] = True
        self._observations.clear()
        self._observe_initial()

    # ------------------------------------------------------------------ #
    # Security-boundary discovery (v0.2 protocol)
    # ------------------------------------------------------------------ #

    def describe_resources(self) -> list[dict]:
        return [
            {
                "id": r.id,
                "name": r.name,
                "type": r.resource_type.value,
                "value": r.value,
                "interfaces": r.interfaces,
            }
            for r in self._resources.values()
        ]

    def describe_actors(self) -> list[dict]:
        return [
            {
                "id": a.id,
                "name": a.name,
                "kind": a.kind.value,
                "description": a.description,
                "entitlements": a.entitlements,
            }
            for a in self._actors.values()
        ]

    def describe_interfaces(self) -> list[dict]:
        return [
            {"name": name, "kind": "api"}
            for name in [
                "chat_api", "stream_api", "job_api",
                "admin_console", "user_api",
            ]
        ]

    def describe_auth_states(self) -> list[dict]:
        return [
            {"name": "unauthenticated"},
            {"name": "free_authenticated"},
            {"name": "paid_authenticated"},
            {"name": "admin_authenticated"},
        ]

    def describe_transitions(self) -> list[dict]:
        return [
            {"from": "unauthenticated", "to": "free_authenticated",
             "trigger": "login:free"},
            {"from": "free_authenticated", "to": "paid_authenticated",
             "trigger": "upgrade"},
            {"from": "unauthenticated", "to": "paid_authenticated",
             "trigger": "login:paid"},
            {"from": "unauthenticated", "to": "admin_authenticated",
             "trigger": "login:admin"},
        ]

    def entitlement_decision(
        self, actor_id: str, resource_id: str, action: str = "access"
    ) -> EntitlementDecision:
        """Return the declared entitlement decision for actor→resource."""
        actor = self._resolve(actor_id, self._actors)
        resource = self._resolve(resource_id, self._resources)
        if actor is None or resource is None:
            return EntitlementDecision.UNKNOWN
        return self._entitlement.get(
            (actor.name, resource.name), EntitlementDecision.DENY
        )

    # ------------------------------------------------------------------ #
    # Proof-session support (v0.3 protocol)
    # ------------------------------------------------------------------ #

    def supports_proof_sessions(self) -> bool:
        """The mock test environment supports proof sessions."""
        return True

    def probe_impact(
        self, actor: str, interface: str, resource: str
    ) -> dict | None:
        """Independently probe whether the protected resource is reachable.

        Used by ImpactVerifier to confirm that a boundary crossing genuinely
        delivers the protected resource payload. Returns the payload if the
        resource was reached, None if access is blocked.
        """
        resolved_actor = self._resolve(actor, self._actors)
        resolved_resource = self._resolve(resource, self._resources)
        if resolved_actor is None or resolved_resource is None:
            return None

        decision = self._entitlement.get(
            (resolved_actor.name, resolved_resource.name),
            EntitlementDecision.DENY,
        )
        enforced = self._enforcement.get((interface, resolved_resource.name), True)

        if decision == EntitlementDecision.ALLOW or not enforced:
            return {
                "resource": resolved_resource.name,
                "payload": (
                    f"{resolved_resource.value} delivered via {interface} "
                    f"to {resolved_actor.name}"
                ),
                "delivered": True,
            }
        return None

    # ------------------------------------------------------------------ #
    # Defender simulation (NOT part of the adapter contract)
    # ------------------------------------------------------------------ #

    def defend(self, weakness_key: str, note: str = "") -> bool:
        """Simulate the defender patching a weakness (v0.1 model)."""
        weakness = self._weaknesses.get(weakness_key)
        if weakness is None:
            return False
        if not weakness.active:
            return False
        weakness.active = False
        if note:
            weakness.defend_note = note
        self._observations.append(
            Observation(
                target_id=self.target_name,
                interface="mock",
                data={
                    "event": "defense_applied",
                    "weakness_key": weakness_key,
                    "note": weakness.defend_note,
                },
                source="mock.defend",
            )
        )
        return True

    def enforce(self, interface: str, resource: str, note: str = "") -> bool:
        """Simulate the defender enforcing a security boundary (v0.2 model).

        Returns True if enforcement was applied (previously-vulnerable
        interface now blocks unauthorized access).
        """
        if (interface, resource) not in self._enforcement:
            return False
        if self._enforcement[(interface, resource)]:
            return False
        self._enforcement[(interface, resource)] = True
        self._observations.append(
            Observation(
                target_id=self.target_name,
                interface=interface,
                data={
                    "event": "boundary_enforced",
                    "resource": resource,
                    "note": note,
                },
                source="mock.enforce",
            )
        )
        return True

    def weaknesses(self) -> dict[str, Weakness]:
        return dict(self._weaknesses)

    def actors(self) -> dict[str, Actor]:
        return dict(self._actors)

    def resources(self) -> dict[str, ProtectedResource]:
        return dict(self._resources)
