"""Impact verification — independent confirmation that a resource was reached.

The proof-credential system is evidence infrastructure, NOT the attack. A
proof session may only be created after ImpactVerifier has independently
confirmed that the finding genuinely reached the protected resource. This
prevents the proof system from becoming an alternative attack mechanism.
"""

from __future__ import annotations

from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    ImpactVerification,
    Target,
)
from opensystem.target.interface import Capability, adapter_capability


class ImpactNotVerified(Exception):
    """Raised when impact verification fails for a finding."""


class ImpactVerifier:
    """Independently re-probes a confirmed finding to verify real impact.

    The verifier does not trust the original test result alone. It re-runs a
    fresh probe against the target adapter and requires the adapter to report
    that the protected resource payload was actually delivered.

    The violated path is resolved from the finding's structured identity
    (actor_id / resource_id / interface) — never by parsing the human-readable
    affected_component display string.
    """

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def verify(
        self,
        finding: Finding,
        target_adapter: object,
        target: Target,
    ) -> ImpactVerification:
        """Run independent impact verification for a finding.

        Returns the ImpactVerification record (persisted — including failed
        verifications, which are part of the audit trail). Raises
        ImpactNotVerified if the resource was not genuinely reached.
        """
        verification = self._verify(finding, target_adapter, target)
        self._store.save_impact_verification(verification)
        if not verification.verified:
            raise ImpactNotVerified(
                f"Impact not verified for finding {finding.id[:8]}: "
                "protected resource was not reached on independent probe."
            )
        return verification

    def _verify(
        self,
        finding: Finding,
        target_adapter: object,
        target: Target,
    ) -> ImpactVerification:
        probe = adapter_capability(
            target_adapter, Capability.IMPACT_PROBE, "probe_impact"
        )
        if probe is None:
            return ImpactVerification(
                finding_id=finding.id,
                verified=False,
                method="adapter-does-not-support-impact-probe",
                detail={
                    "reason": "target adapter lacks the impact_probe capability"
                },
            )

        params = self._finding_path_params(finding)
        if params is None:
            return ImpactVerification(
                finding_id=finding.id,
                verified=False,
                method="finding-path-unresolvable",
                detail={
                    "reason": (
                        "finding carries no structured actor/resource/"
                        "interface identity and legacy text is not parsed"
                    )
                },
            )

        # A probe that raises is an adapter implementation error: it must
        # surface as an error, never as a recorded "not verified" outcome.
        payload = probe(**params)

        reached = bool(payload)
        verification = ImpactVerification(
            finding_id=finding.id,
            verified=reached,
            method="independent-impact-probe",
            detail={
                "actor": params.get("actor"),
                "interface": params.get("interface"),
                "resource": params.get("resource"),
                "payload": payload if reached else None,
            },
        )

        # Record evidence for the verification regardless of outcome.
        self._store.save_evidence(
            Evidence(
                kind=EvidenceKind.OBSERVATION,
                data={
                    "event": "impact_verification",
                    "verified": reached,
                    "method": verification.method,
                },
                reference=f"impact:{verification.id}",
            )
        )

        return verification

    @staticmethod
    def _finding_path_params(finding: Finding) -> dict | None:
        """Resolve the violated path from the finding's structured identity.

        Returns probe parameters, or None when the finding has no structured
        identity (e.g. a legacy weakness-model finding). Presentation strings
        are not data relationships and are never parsed here.
        """
        if finding.actor_id and finding.resource_id and finding.interface:
            return {
                "actor": finding.actor_id,
                "interface": finding.interface,
                "resource": finding.resource_id,
            }
        return None


# Convenience: mark a finding CONFIRMED after impact verification succeeds.
def confirm_finding(store: KnowledgeStore, finding_id: str) -> None:
    """Transition a finding to CONFIRMED (impact verification passed)."""
    store.update_finding_status(finding_id, FindingStatus.CONFIRMED)
