"""A deterministic mock target demonstrating the full adversarial lifecycle.

The mock target is intentionally simple and deterministic. It models a system
as a set of weaknesses, each of which can be *active* (exploitable) or
*blocked* (defended). This is enough to exercise every stage of the
OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST → ANALYZE → EVOLVE loop without
any real network or software risk.

Design intent
-------------
- It is a REAL implementation of the TargetAdapter contract.
- It is NOT an autonomous attacker; it is a controllable stand-in so the core
  engine can be developed and tested before connecting real targets.
- The `defend()` method simulates the defender patching a weakness, which lets
  us demonstrate learning-from-failure and the evolution cycle.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from openmodels.models import (
    Evidence,
    EvidenceKind,
    Observation,
    Severity,
    Target,
    TestOutcome,
    TestResult,
    TestSpec,
    utcnow,
)
from openmodels.target.interface import TargetAdapter


class Weakness(BaseModel):
    """A known weakness in the mock target."""

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
    """Deterministic target with configurable weaknesses.

    Test protocol
    -------------
    A test must provide ``parameters`` with a ``weakness`` key naming one of
    the target's weaknesses. The outcome is:

      - SUCCESS     if the weakness is active
      - FAILURE     if the weakness is blocked by a defense
      - INCONCLUSIVE if the named weakness does not exist

    After ``defend()`` is called for a weakness, the previously-successful
    hypothesis must be re-tested and observed to fail — this is the regression
    step of the adversarial loop.
    """

    name = "mock"

    def __init__(self, name: str = "mock-service", version: str = "0.1.0"):
        self.target_name = name
        self.target_version = version
        self._target_id: str | None = None
        self._weaknesses: dict[str, Weakness] = {}
        self._observations: list[Observation] = []
        self._last_result: TestResult | None = None
        self._seed_weaknesses()
        self._observe_initial()

    # ------------------------------------------------------------------ #
    # Seed data
    # ------------------------------------------------------------------ #

    def _seed_weaknesses(self) -> None:
        seeds = [
            Weakness(
                key="auth-bypass",
                name="authentication bypass via default credential",
                component="auth",
                severity=Severity.CRITICAL,
                description=(
                    "The authentication layer accepts the well-known default "
                    "administrator credential."
                ),
                success_message="Default admin credential accepted.",
                block_message="Authentication layer rejected the default credential.",
                defend_note="Rotated default credential and enforced credential policy.",
            ),
            Weakness(
                key="authz-ownership",
                name="horizontal privilege escalation on object ownership",
                component="authz",
                severity=Severity.HIGH,
                description=(
                    "Object ownership is not checked; any authenticated "
                    "principal can read another principal's objects."
                ),
                success_message="Read another principal's object without authorization.",
                block_message="Central authorization layer rejected cross-principal access.",
                defend_note="Added central ownership checks at the authorization layer.",
            ),
            Weakness(
                key="input-traversal",
                name="path traversal in file retrieval endpoint",
                component="storage",
                severity=Severity.HIGH,
                description=(
                    "The retrieval endpoint does not canonicalize paths, "
                    "allowing traversal outside the data directory."
                ),
                success_message="Retrieved file outside the data directory.",
                block_message="Path canonicalization rejected the traversal.",
                defend_note="Canonicalize and constrain paths before access.",
            ),
            Weakness(
                key="resource-abuse",
                name="unbounded resource consumption on pagination",
                component="api",
                severity=Severity.MEDIUM,
                description=(
                    "Pagination is unbounded; a single request can trigger "
                    "excessive resource usage."
                ),
                success_message="Triggered unbounded pagination scan.",
                block_message="Rate and size limits rejected the oversized request.",
                defend_note="Enforced pagination and rate limits.",
            ),
            Weakness(
                key="agent-tool-boundary",
                name="agent tool boundary escape",
                component="agent",
                severity=Severity.HIGH,
                description=(
                    "The agent's tool router does not validate the requested "
                    "tool against the granted tool set."
                ),
                success_message="Invoked a tool outside the agent's granted set.",
                block_message="Tool boundary enforcement rejected the invocation.",
                defend_note="Constrained the agent tool router to the granted tool set.",
            ),
            Weakness(
                key="session-fixation",
                name="session fixation via unvalidated session id",
                component="session",
                severity=Severity.MEDIUM,
                description=(
                    "The session layer accepts a client-supplied session id "
                    "without re-issuing it after authentication."
                ),
                success_message="Fixed a session id accepted post-authentication.",
                block_message="Session layer re-issued the session id.",
                defend_note="Re-issue session ids on authentication.",
            ),
            Weakness(
                key="state-transition",
                name="illegal state transition in workflow",
                component="workflow",
                severity=Severity.MEDIUM,
                description=(
                    "The workflow engine does not validate the requested state "
                    "transition against the allowed set."
                ),
                success_message="Performed an illegal workflow state transition.",
                block_message="Workflow engine rejected the illegal transition.",
                defend_note="Enforce the allowed state-transition table.",
            ),
            Weakness(
                key="dependency-supply-chain",
                name="unpinned transitive dependency",
                component="dependencies",
                severity=Severity.HIGH,
                description=(
                    "A transitive dependency is resolved with an unpinned "
                    "range, allowing supply-chain substitution."
                ),
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
    # TargetAdapter contract
    # ------------------------------------------------------------------ #

    def discover(self) -> Target:
        if self._target_id is None:
            self._target_id = Target(
                name=self.target_name,
                kind="mock",
                adapter=self.name,
                version=self.target_version,
            ).id
        return Target(
            id=self._target_id,
            name=self.target_name,
            kind="mock",
            adapter=self.name,
            version=self.target_version,
            description=(
                "Deterministic mock system with seeded weaknesses, used to "
                "exercise the adversarial engine."
            ),
            assets=[w.key for w in self._weaknesses.values()],
            interfaces=["mock"],
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
        }

    def execute_test(self, test: TestSpec) -> TestResult:
        weakness_key = (test.parameters or {}).get("weakness")
        if not weakness_key:
            return TestResult(
                outcome=TestOutcome.ERROR,
                observed_result="Test had no 'weakness' parameter.",
                detail={"error": "malformed-test"},
            )
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
        self._observations.clear()
        self._observe_initial()

    # ------------------------------------------------------------------ #
    # Defender simulation (NOT part of the adapter contract)
    # ------------------------------------------------------------------ #

    def defend(self, weakness_key: str, note: str = "") -> bool:
        """Simulate the defender patching a weakness.

        Returns True if a defense was applied (weakness now blocked).
        """
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

    def weaknesses(self) -> dict[str, Weakness]:
        return dict(self._weaknesses)
