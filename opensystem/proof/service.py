"""Proof session service — show-once attack-proof credential system.

The proof credential is a short-lived, single-display, strictly-scoped
credential for the AUTHORIZED TEST TARGET only. It is bound to a specific
confirmed finding and the affected actor/resource, and it never grants
elevated privileges.

Cryptographic design
--------------------
Key generation:  CSPRNG via secrets.token_hex(32) → 256-bit secret.
Key format:      omk_<session_id>_<secret>
Storage:         SHA-256 hash of the full key.
Justification:   For high-entropy (256-bit) CSPRNG-generated secrets, SHA-256
                 is the appropriate, NIST-aligned choice (NIST SP 800-107).
                 Slow KDFs (bcrypt/argon2) are designed for low-entropy
                 passwords and add no benefit when the input already has
                 full cryptographic entropy. The session ID is stored in the
                 clear for lookup; the secret provides the authentication
                 factor.

The affected actor and resource are resolved from the finding's structured
identity (actor_id / resource_id) — presentation strings are never parsed.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import secrets

from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Actor,
    CaseStudy,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    ProofSession,
    ProofSessionResult,
    ProofSessionStatus,
    ProofVerification,
    ProtectedResource,
    Target,
    new_id,
    utcnow,
)
from opensystem.policy.engine import PolicyEnforcer
from opensystem.policy.models import Operation, Policy
from opensystem.target.interface import (
    Capability,
    adapter_capability,
    adapter_supports,
)


class ProofKeyError(Exception):
    """Raised when a proof-key operation is invalid."""


def mask_key(session: ProofSession) -> str:
    """Return the masked, display-safe representation of a proof key.

    The key format is ``omk_<session_id>_<secret>``; the session id IS the key
    identifier, so the mask shows it and hides the secret entirely:

        omk_a1b2c3d4e5f67890...

    The raw secret is never recoverable from this representation.
    """
    return f"omk_{session.id}..."


class ProofSessionService:
    """Manages show-once proof credentials for confirmed findings."""

    def __init__(self, store: KnowledgeStore, policy: Policy | None = None) -> None:
        self._store = store
        self._policy = policy or Policy()
        self._enforcer = PolicyEnforcer(self._policy)
        self._default_expiry_hours = 24

    # ------------------------------------------------------------------ #
    # Create — show once
    # ------------------------------------------------------------------ #

    def create(
        self,
        finding: Finding,
        target_adapter: object,
        target: Target,
        campaign_id: str = "",
        expires_hours: int | None = None,
    ) -> ProofSessionResult:
        """Create a show-once proof session for a confirmed finding.

        Gating checks (all must pass):
          1. Finding exists and is CONFIRMED.
          2. Impact verification succeeded (latest ImpactVerification.verified).
          3. Target adapter declares the proof_session capability.
          4. Policy permits PROOF_SESSION.
          5. The affected actor and resource are resolvable.

        Returns ProofSessionResult with the raw key (shown once).
        """
        # Gate 1: finding status.
        if finding.verification_status != FindingStatus.CONFIRMED:
            raise ProofKeyError(
                f"Finding {finding.id[:8]} must be CONFIRMED "
                f"(status={finding.verification_status.value})."
            )

        # Gate 2: impact verification.
        verifications = self._store.get_impact_verifications(finding.id)
        if not verifications or not verifications[0].verified:
            raise ProofKeyError(
                f"Finding {finding.id[:8]} has no passing impact verification. "
                "Run impact verification first."
            )

        # Gate 3: adapter support.
        if not adapter_supports(target_adapter, Capability.PROOF_SESSION):
            raise ProofKeyError(
                "Target adapter does not support proof sessions."
            )

        # Gate 4: policy.
        self._enforcer.check(Operation.PROOF_SESSION, target)

        # Gate 5: resolve actor and resource from the finding's structured
        # identity.
        actor = self._resolve_actor(finding, target_adapter)
        resource = self._resolve_resource(finding, target_adapter)
        if actor is None:
            raise ProofKeyError("Cannot resolve affected actor from finding.")
        if resource is None:
            raise ProofKeyError(
                "Cannot resolve affected resource from finding."
            )

        # Generate the proof credential.
        session_id = new_id()
        secret = secrets.token_hex(32)  # 256-bit secret
        raw_key = f"omk_{session_id}_{secret}"
        username = f"proof_{actor.name}_{session_id[:6]}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        if expires_hours is not None and expires_hours < 0:
            raise ProofKeyError("expires_hours must not be negative.")
        expires = utcnow() + datetime.timedelta(
            hours=(
                expires_hours
                if expires_hours is not None
                else self._default_expiry_hours
            )
        )

        session = ProofSession(
            id=session_id,
            finding_id=finding.id,
            campaign_id=campaign_id,
            target_id=target.id,
            target_adapter=getattr(target_adapter, "name", target.adapter),
            actor_id=actor.id,
            resource_id=resource.id,
            username=username,
            key_hash=key_hash,
            status=ProofSessionStatus.ACTIVE,
            expires_at=expires,
        )

        # Persist the binding records and the session atomically so every
        # reader (inspect, case study, audit) can resolve the actor/resource
        # the key is bound to.
        with self._store.transaction():
            self._store.save_actor(actor)
            self._store.save_protected_resource(resource)
            self._store.save_proof_session(session)

        return ProofSessionResult(session=session, raw_key=raw_key)

    # ------------------------------------------------------------------ #
    # Verify — presented key validation
    # ------------------------------------------------------------------ #

    def verify(
        self,
        raw_key: str,
        expected_target_id: str | None = None,
        expected_finding_id: str | None = None,
        expected_actor_id: str | None = None,
    ) -> ProofVerification:
        """Validate a presented proof key through the full pipeline.

        Steps (per the show-once validation contract):
          1. Parse the key format and identify the key record.
          2. Hash/verify the presented secret.
          3. Check expiration.
          4. Check revocation.
          5. Check target binding.
          6. Check finding binding.
          7. Check actor binding.
          8. Authenticate and record usage + evidence.

        Optional ``expected_*`` parameters enforce the attack-proof binding:
        an interface that knows which target/finding/actor it expects can
        reject a key bound to something else. The raw key is never included
        in any failure reason.
        """
        # 1. Parse the key format and identify the key record.
        try:
            parts = raw_key.split("_")
            if len(parts) != 3 or parts[0] != "omk":
                return ProofVerification(ok=False, reason="invalid-key-format")
            session_id = parts[1]
            presented_secret = parts[2]
        except (IndexError, ValueError):
            return ProofVerification(ok=False, reason="invalid-key-format")

        session = self._store.get_proof_session(session_id)
        if session is None:
            return ProofVerification(ok=False, reason="session-not-found")

        # 2. Hash the presented key and compare (constant-time).
        reconstructed = f"omk_{session_id}_{presented_secret}"
        presented_hash = hashlib.sha256(reconstructed.encode()).hexdigest()
        if not hmac.compare_digest(presented_hash, session.key_hash):
            return ProofVerification(ok=False, reason="key-mismatch")

        now = utcnow()

        # 3. Check revocation BEFORE expiry so a revoked session is never
        #    re-classified as expired (revocation is the stronger state).
        if session.status == ProofSessionStatus.REVOKED:
            return ProofVerification(
                ok=False, session=session, reason="session-revoked"
            )

        # 4. Check expiration.
        if session.expires_at < now or session.status == ProofSessionStatus.EXPIRED:
            if session.status != ProofSessionStatus.EXPIRED:
                self._store.update_proof_session_status(
                    session_id, ProofSessionStatus.EXPIRED
                )
                session.status = ProofSessionStatus.EXPIRED
            return ProofVerification(
                ok=False, session=session, reason="expired"
            )

        # 5-7. Binding checks: target, finding, actor.
        if expected_target_id is not None and session.target_id != expected_target_id:
            return ProofVerification(ok=False, session=session, reason="target-mismatch")
        if expected_finding_id is not None and session.finding_id != expected_finding_id:
            return ProofVerification(ok=False, session=session, reason="finding-mismatch")
        if expected_actor_id is not None and session.actor_id != expected_actor_id:
            return ProofVerification(ok=False, session=session, reason="actor-mismatch")

        # 8. Record usage (audit trail). The key remains valid until expiry
        #    or revocation so the researcher may re-authenticate to
        #    demonstrate impact within the authorized window.
        self._store.touch_proof_session(session_id)
        session.last_used_at = utcnow()

        # Capture authentication evidence and attach it to the finding.
        evidence = Evidence(
            kind=EvidenceKind.ARTIFACT,
            data={
                "event": "proof_key_authenticated",
                "session_id": session.id,
                "finding_id": session.finding_id,
                "target_id": session.target_id,
                "actor_id": session.actor_id,
                "resource_id": session.resource_id,
                "authenticated_at": session.last_used_at.isoformat(),
                # Raw key intentionally NEVER recorded.
            },
            reference=f"proof:{session.id}",
        )
        with self._store.transaction():
            self._store.save_evidence(evidence)
            finding = self._store.get_finding(session.finding_id)
            if finding is not None and evidence.id not in finding.evidence_ids:
                finding.evidence_ids.append(evidence.id)
                self._store.save_finding(finding)

        return ProofVerification(ok=True, session=session, reason="authenticated")

    # ------------------------------------------------------------------ #
    # Read / list / revoke (masked — never return raw key)
    # ------------------------------------------------------------------ #

    def inspect(self, session_id: str) -> ProofSession | None:
        """Return a proof session with masked key (read-only).

        The returned record never carries the raw key: only the masked key
        representation and a truncated hash are exposed. The stored record
        itself is untouched — masking is applied to a copy so a masked hash
        can never be persisted back by a later save.
        """
        session = self._store.get_proof_session(session_id)
        if session is None:
            return None
        return self._mask(session)

    def list(self) -> list[ProofSession]:
        """List all proof sessions (masked)."""
        return [self._mask(s) for s in self._store.list_proof_sessions()]

    def revoke(self, session_id: str) -> ProofSession | None:
        """Revoke a proof session immediately.

        The credential fails validation from this moment on. The historical
        record (including revoked_at) is preserved.
        """
        session = self._store.get_proof_session(session_id)
        if session is None:
            return None
        if session.status in (ProofSessionStatus.EXPIRED, ProofSessionStatus.REVOKED):
            return session
        revoked_at = utcnow()
        self._store.revoke_proof_session(session_id, revoked_at)
        session.status = ProofSessionStatus.REVOKED
        session.revoked_at = revoked_at
        return session

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _mask(session: ProofSession) -> ProofSession:
        """Return a copy of the session with the key hash truncated."""
        return session.model_copy(
            update={"key_hash": session.key_hash[:8] + "..."}
        )

    def _resolve_actor(
        self, finding: Finding, target_adapter: object
    ) -> Actor | None:
        """Resolve the affected actor from the finding's structured identity.

        The store is authoritative; adapters declaring a security model may
        supply the record when it has not been persisted yet (it is persisted
        by create()).
        """
        if not finding.actor_id:
            return None
        actor = self._store.get_actor(finding.actor_id)
        if actor is not None:
            return actor
        actors_fn = adapter_capability(
            target_adapter, Capability.SECURITY_MODEL, "actors"
        )
        if actors_fn is None:
            return None
        models = actors_fn()
        return models.get(finding.actor_id) or next(
            (a for a in models.values() if a.id == finding.actor_id), None
        )

    def _resolve_resource(
        self, finding: Finding, target_adapter: object
    ) -> ProtectedResource | None:
        """Resolve the affected resource from the finding's structured identity."""
        if not finding.resource_id:
            return None
        resource = self._store.get_protected_resource(finding.resource_id)
        if resource is not None:
            return resource
        resources_fn = adapter_capability(
            target_adapter, Capability.SECURITY_MODEL, "resources"
        )
        if resources_fn is None:
            return None
        models = resources_fn()
        return models.get(finding.resource_id) or next(
            (r for r in models.values() if r.id == finding.resource_id), None
        )


# ------------------------------------------------------------------ #
# Case study builder
# ------------------------------------------------------------------ #

def build_case_study(
    store: KnowledgeStore,
    finding: Finding,
    target_adapter: object,
    target: Target,
    campaign_id: str = "",
) -> CaseStudy:
    """Assemble a reproducible case study for a finding from real store data.

    Every section is derived from persisted records — experiments, evidence,
    attack surface, hypotheses, defenses — not from placeholders. Impact
    verification status is reported exactly as the store records it: a case
    study never claims verification that did not happen. The report NEVER
    contains the raw proof key: only proof-session metadata.
    """
    campaign = store.get_campaign(campaign_id) if campaign_id else None

    # --- Actor / resource records -----------------------------------
    # Structured identity first; proof-session bindings as fallback.
    actor = (
        store.get_actor(finding.actor_id) if finding.actor_id else None
    )
    resource = (
        store.get_protected_resource(finding.resource_id)
        if finding.resource_id
        else None
    )
    sessions = store.list_proof_sessions()
    proof = next((s for s in sessions if s.finding_id == finding.id), None)
    if proof is not None:
        if actor is None:
            actor = store.get_actor(proof.actor_id)
        if resource is None:
            resource = store.get_protected_resource(proof.resource_id)

    def _component_part(part: int) -> str:
        pieces = finding.affected_component.split("→")
        return pieces[part].strip() if len(pieces) > part else finding.affected_component

    # --- Impact verification status (evidence-derived) -----------------
    verifications = store.get_impact_verifications(finding.id)
    latest_verification = verifications[0] if verifications else None
    if latest_verification is None:
        impact_status = "unknown"
        impact_summary = (
            "No independent impact verification on record for this finding."
        )
    elif latest_verification.verified:
        impact_status = "verified"
        impact_summary = (
            "Impact independently verified: a fresh probe confirmed the "
            "protected resource was reached."
        )
    else:
        impact_status = "not_verified"
        impact_summary = (
            "Independent impact verification did NOT confirm that the "
            "protected resource was reached."
        )

    # --- Real experiments and hypotheses ------------------------------
    experiments = store.get_experiments_by_hypothesis(finding.hypothesis_id) \
        if finding.hypothesis_id else []
    hypothesis = (
        store.get_hypothesis(finding.hypothesis_id)
        if finding.hypothesis_id else None
    )

    # --- Real evidence -------------------------------------------------
    evidence_records = [
        store.get_evidence(eid)
        for eid in finding.evidence_ids
    ]
    evidence_records = [e for e in evidence_records if e is not None]

    # --- Attack surface -------------------------------------------------
    surface = store.get_attack_surface(target.id)
    surface_interfaces = [
        i.get("name", str(i)) for i in (surface.interfaces if surface else [])
    ]
    discovered_paths = sum(
        len(store.list_attack_paths(campaign_id=c.id))
        for c in store.list_campaigns()
        if c.target_id == target.id
    )

    # --- Defenses and regression status ---------------------------------
    defenses = store.list_defenses(finding.id)

    report = {
        "research_question": finding.attack_hypothesis,
        "target": {
            "name": target.name,
            "adapter": target.adapter,
            "id": target.id,
            "version": target.version,
            "description": target.description,
        },
        "campaign_id": campaign.id if campaign else "",
        "authorization_scope": (
            f"Authorized test environment: target '{target.name}' "
            f"(adapter={target.adapter}); all testing confined to this target."
        ),
        "actor": {
            "name": actor.name if actor else _component_part(0),
            "kind": actor.kind.value if actor else "unknown",
            "entitlements": actor.entitlements if actor else [],
        },
        "protected_resource": {
            "name": resource.name if resource else _component_part(-1),
            "type": resource.resource_type.value if resource else "unknown",
            "value": resource.value if resource else "",
        },
        "methodology": (
            "Adversarial campaign: hypothesis-driven security-boundary "
            "testing. Each hypothesis was tested experimentally. A finding "
            "is promoted to CONFIRMED only after an independent impact probe "
            "reaches the protected resource; the verification status of this "
            "finding is recorded below."
        ),
        "impact_verification": {
            "status": impact_status,
            "method": (
                latest_verification.method if latest_verification else ""
            ),
            "summary": impact_summary,
        },
        "attack_surface": {
            "interfaces": surface_interfaces,
            "discovered_paths": discovered_paths,
        },
        "hypotheses": (
            [hypothesis.statement] if hypothesis else [finding.attack_hypothesis]
        ),
        "attack_path": finding.affected_component,
        "experiments": [
            {
                "id": e.id,
                "test": e.test.name,
                "outcome": e.outcome.value,
                "observed": e.observed_result,
            }
            for e in experiments
        ],
        "evidence": [
            {
                "id": e.id,
                "kind": e.kind.value,
                "reference": e.reference,
                "captured_at": e.captured_at.isoformat(),
            }
            for e in evidence_records
        ],
        "finding": {
            "id": finding.id,
            "severity": finding.severity.value,
            "status": finding.verification_status.value,
            "impact": finding.impact,
            "observed_behavior": finding.observed_behavior,
        },
        "proof_session": (
            {
                "id": proof.id,
                "username": proof.username,
                "status": proof.status.value,
                "created_at": proof.created_at.isoformat(),
                "expires_at": proof.expires_at.isoformat(),
                # Raw key NEVER included — only metadata.
            }
            if proof else None
        ),
        "remediation": finding.recommended_mitigation,
        "defense_verification": (
            {
                "defenses_applied": len(defenses),
                "descriptions": [d.description for d in defenses],
            }
            if defenses
            else "No defenses applied yet; revalidate after enforcement."
        ),
        "conclusion": (
            f"Security boundary violated: {finding.attack_hypothesis}. "
            f"Impact verification status: {impact_status}. "
            f"Mitigation: {finding.recommended_mitigation}"
        ),
    }

    cs = CaseStudy(
        finding_id=finding.id,
        title=f"Case Study: {finding.affected_component}",
        body=report,
    )
    store.save_case_study(cs)
    return cs
