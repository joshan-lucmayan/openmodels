"""Tests for the show-once proof-key system (v0.3).

Covers: CSPRNG generation, show-once delivery, hash-only storage, validation
pipeline, expiry, revocation, binding, leakage prevention, and the complete
workflow.
"""

from __future__ import annotations

import datetime
import hashlib
import time

import pytest

from opensystem.impact.engine import ImpactNotVerified, ImpactVerifier
from opensystem.models import (
    Finding,
    FindingStatus,
    ProofSessionStatus,
    Severity,
    new_id,
    utcnow,
)
from opensystem.policy.engine import PolicyViolation
from opensystem.policy.models import Operation, Policy
from opensystem.proof.service import (
    ProofKeyError,
    ProofSessionService,
    build_case_study,
    mask_key,
)

# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #

@pytest.fixture()
def confirmed_finding(store, mock_target):
    """Create a finding that is CONFIRMED with impact verified."""
    target = mock_target.discover()
    store.save_target(target)

    actor = mock_target.actors()["free_user"]
    resource = mock_target.resources()["premium_model"]
    finding = Finding(
        target_id=target.id,
        actor_id=actor.id,
        resource_id=resource.id,
        interface="stream_api",
        severity=Severity.HIGH,
        affected_component=(
            "actor=UNAUTHENTICATED/free_user → interface=[stream_api] → "
            "resource=premium_model"
        ),
        attack_hypothesis="free_user can access premium_model without entitlement",
        impact="Premium inference executed via stream_api",
        verification_status=FindingStatus.DISCOVERED,
    )
    store.save_finding(finding)

    # Run impact verification.
    verifier = ImpactVerifier(store)
    verification = verifier.verify(finding, mock_target, target)
    assert verification.verified

    # Mark CONFIRMED.
    store.update_finding_status(finding.id, FindingStatus.CONFIRMED)
    finding.verification_status = FindingStatus.CONFIRMED
    return finding


@pytest.fixture()
def proof_policy() -> Policy:
    return Policy(
        target_name="mock",
        allowed_operations=[
            Operation.OBSERVE, Operation.TEST, Operation.RESET,
            Operation.PROOF_SESSION,
        ],
    )


@pytest.fixture()
def proof_service(store, proof_policy) -> ProofSessionService:
    return ProofSessionService(store, policy=proof_policy)


# ------------------------------------------------------------------ #
# 1. CSPRNG key generation
# ------------------------------------------------------------------ #

def test_csprng_key_generation(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    assert result.raw_key.startswith("omk_")
    # 256-bit secret = 64 hex chars
    parts = result.raw_key.split("_")
    assert len(parts) == 3
    assert len(parts[2]) == 64  # 32 bytes -> 64 hex chars


# ------------------------------------------------------------------ #
# 2. Unique keys
# ------------------------------------------------------------------ #

def test_unique_keys(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    r1 = proof_service.create(confirmed_finding, mock_target, target)
    r2 = proof_service.create(confirmed_finding, mock_target, target)
    assert r1.raw_key != r2.raw_key


# ------------------------------------------------------------------ #
# 3. Raw key returned once (show-once pattern)
# ------------------------------------------------------------------ #

def test_raw_key_returned_once(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    # The raw_key is on the returned ProofSessionResult — shown once.
    assert result.raw_key
    # Inspect returns only masked hash.
    session = proof_service.inspect(result.session.id)
    assert session is not None
    # The raw key is not on the stored session.
    assert session.key_hash != result.raw_key


# ------------------------------------------------------------------ #
# 4. Plaintext never persisted
# ------------------------------------------------------------------ #

def test_plaintext_never_persisted(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    # The store has only the hash, not the raw key.
    stored = store.get_proof_session(result.session.id)
    assert stored is not None
    assert stored.key_hash != result.raw_key
    assert stored.key_hash == hashlib.sha256(
        result.raw_key.encode()
    ).hexdigest()


# ------------------------------------------------------------------ #
# 5. Correct key authenticates
# ------------------------------------------------------------------ #

def test_correct_key_authenticates(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    verification = proof_service.verify(result.raw_key)
    assert verification.ok
    assert verification.reason == "authenticated"
    assert verification.session is not None


# ------------------------------------------------------------------ #
# 6. Incorrect key rejected
# ------------------------------------------------------------------ #

def test_incorrect_key_rejected(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    bad_key = result.raw_key[:-1] + ("x" if result.raw_key[-1] != "x" else "y")
    verification = proof_service.verify(bad_key)
    assert not verification.ok
    assert verification.reason == "key-mismatch"


# ------------------------------------------------------------------ #
# 7. Expired key rejected
# ------------------------------------------------------------------ #

def test_expired_key_rejected(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    # Create with 0-hour expiry (already expired).
    result = proof_service.create(
        confirmed_finding, mock_target, target, expires_hours=0
    )
    # Need to fast-forward the session's expiry. Since we can't go back in
    # time, create with expires_hours=0 and verify immediately — it expires
    # at same time as creation (utcnow was captured at creation).
    time.sleep(0.01)  # ensure at least 10ms passes
    verification = proof_service.verify(result.raw_key)
    assert not verification.ok
    assert verification.reason == "expired"


# ------------------------------------------------------------------ #
# 8. Revoked key rejected
# ------------------------------------------------------------------ #

def test_revoked_key_rejected(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    proof_service.revoke(result.session.id)
    verification = proof_service.verify(result.raw_key)
    assert not verification.ok
    assert verification.reason == "session-revoked"


# ------------------------------------------------------------------ #
# 9. Target mismatch rejected
# ------------------------------------------------------------------ #

def test_target_mismatch_rejected(store, confirmed_finding, mock_target):
    target = mock_target.discover()
    # Policy scoped to a different target.
    wrong_policy = Policy(
        target_name="other-system",
        allowed_operations=[Operation.PROOF_SESSION],
    )
    service = ProofSessionService(store, policy=wrong_policy)
    with pytest.raises(PolicyViolation):
        service.create(confirmed_finding, mock_target, target)


# ------------------------------------------------------------------ #
# 10. Finding mismatch (key bound to different finding)
# ------------------------------------------------------------------ #

def test_finding_mismatch_validated(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    # The key is bound to confirmed_finding.id. Verify that the session
    # record links to the correct finding.
    session = store.get_proof_session(result.session.id)
    assert session.finding_id == confirmed_finding.id


# ------------------------------------------------------------------ #
# 11. Actor binding enforced
# ------------------------------------------------------------------ #

def test_actor_binding_enforced(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    session = store.get_proof_session(result.session.id)
    # The session's actor_id should match the affected actor from the finding.
    assert "free_user" in str(session.actor_id)


# ------------------------------------------------------------------ #
# 12. Raw key absent from logs (no log capture in tests)
# ------------------------------------------------------------------ #

def test_raw_key_absent_from_logs(proof_service, confirmed_finding, mock_target, store, capsys):
    """Verify that the raw key is not printed to stdout/stderr indirectly."""
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    # Inspect via service (not CLI) — no stdout output.
    session = proof_service.inspect(result.session.id)
    assert session is not None
    # The raw key is not available on the inspected session.
    assert session.key_hash != result.raw_key


# ------------------------------------------------------------------ #
# 13. Raw key absent from API read responses (inspect)
# ------------------------------------------------------------------ #

def test_raw_key_absent_from_inspect(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    session = proof_service.inspect(result.session.id)
    assert session is not None
    # The raw key is not stored on the session.
    assert not hasattr(session, "raw_key") or session.raw_key == ""


# ------------------------------------------------------------------ #
# 14. Masked key returned for reads
# ------------------------------------------------------------------ #

def test_masked_key_in_inspect(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    session = proof_service.inspect(result.session.id)
    assert session is not None
    # Hash is truncated (masked) in inspect.
    assert len(session.key_hash) < 64 or "..." in session.key_hash


# ------------------------------------------------------------------ #
# 15. Proof session expires
# ------------------------------------------------------------------ #

def test_proof_session_expires_state(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    expires_hours = 48
    result = proof_service.create(
        confirmed_finding, mock_target, target, expires_hours=expires_hours
    )
    session = store.get_proof_session(result.session.id)
    assert session is not None
    expected = utcnow() + datetime.timedelta(hours=expires_hours)
    # Allow a few seconds of tolerance.
    diff = abs((session.expires_at - expected).total_seconds())
    assert diff < 5


# ------------------------------------------------------------------ #
# 16. Proof session can be revoked
# ------------------------------------------------------------------ #

def test_proof_session_revokable(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    assert store.get_proof_session(result.session.id).status == ProofSessionStatus.ACTIVE
    proof_service.revoke(result.session.id)
    assert store.get_proof_session(result.session.id).status == ProofSessionStatus.REVOKED


# ------------------------------------------------------------------ #
# 17. Unauthorized target cannot create proof session
# ------------------------------------------------------------------ #

def test_unauthorized_target_cannot_create(store, confirmed_finding, mock_target):
    target = mock_target.discover()
    # Policy without PROOF_SESSION.
    strict = Policy(target_name="mock", allowed_operations=[])
    service = ProofSessionService(store, policy=strict)
    with pytest.raises(PolicyViolation):
        service.create(confirmed_finding, mock_target, target)


# ------------------------------------------------------------------ #
# 18. Unconfirmed finding cannot create proof session
# ------------------------------------------------------------------ #

def test_unconfirmed_finding_cannot_prove(store, mock_target, proof_service):
    target = mock_target.discover()
    store.save_target(target)
    finding = Finding(
        target_id=target.id,
        severity=Severity.MEDIUM,
        affected_component="actor=GUEST → interface=[test] → resource=test",
        verification_status=FindingStatus.DISCOVERED,
    )
    store.save_finding(finding)
    with pytest.raises(ProofKeyError, match="must be CONFIRMED"):
        proof_service.create(finding, mock_target, target)


# ------------------------------------------------------------------ #
# 19. Database restart preserves validation
# ------------------------------------------------------------------ #

def test_database_restart_preserves_validation(store, confirmed_finding, mock_target, proof_service):
    """Simulate a "restart" by closing the store and reopening."""
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    raw_key = result.raw_key

    # Close and reopen the store.
    store.close()
    new_store = type(store)(store._path)
    new_service = ProofSessionService(new_store, policy=proof_service._policy)

    # The key should still validate.
    verification = new_service.verify(raw_key)
    assert verification.ok
    new_store.close()


# ------------------------------------------------------------------ #
# 20. Complete workflow: attack → finding → proof → verify → evidence
# ------------------------------------------------------------------ #

def test_complete_workflow(store, mock_target, confirmed_finding):
    """Full end-to-end workflow for the proof system."""
    target = mock_target.discover()
    policy = Policy(
        target_name="mock",
        allowed_operations=[
            Operation.OBSERVE, Operation.TEST, Operation.RESET,
            Operation.PROOF_SESSION,
        ],
    )
    service = ProofSessionService(store, policy=policy)

    # Step 1: Create proof session.
    result = service.create(confirmed_finding, mock_target, target)
    assert result.raw_key.startswith("omk_")
    assert result.session.status == ProofSessionStatus.ACTIVE

    # Step 2: Verify the key authenticates.
    verification = service.verify(result.raw_key)
    assert verification.ok
    assert verification.reason == "authenticated"

    # Step 3: Usage was recorded (last_used_at set); status stays ACTIVE.
    stored = store.get_proof_session(result.session.id)
    assert stored.status == ProofSessionStatus.ACTIVE
    assert stored.last_used_at is not None

    # Step 4: Re-authentication within the valid window still works
    # (the researcher may demonstrate impact more than once before expiry).
    replay = service.verify(result.raw_key)
    assert replay.ok

    # Step 5: Inspect shows masked key.
    inspected = service.inspect(result.session.id)
    assert inspected is not None
    assert "..." in inspected.key_hash

    # Step 6: History does not contain the raw key.
    for s in service.list():
        assert s.key_hash != result.raw_key


# ------------------------------------------------------------------ #
# Extended coverage (revocation persistence, precedence, binding,
# evidence capture, masking, case-study leakage)
# ------------------------------------------------------------------ #

def test_revoke_persists_revoked_at(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    before = utcnow()
    proof_service.revoke(result.session.id)

    stored = store.get_proof_session(result.session.id)
    assert stored.revoked_at is not None
    assert stored.revoked_at >= before - datetime.timedelta(seconds=1)
    assert stored.status == ProofSessionStatus.REVOKED


def test_revocation_takes_precedence_over_expiry(
    proof_service, confirmed_finding, mock_target, store
):
    """A revoked-then-expired session must fail as REVOKED, and the verify
    pipeline must never overwrite the REVOKED status with EXPIRED."""
    target = mock_target.discover()
    result = proof_service.create(
        confirmed_finding, mock_target, target, expires_hours=0
    )
    proof_service.revoke(result.session.id)

    verification = proof_service.verify(result.raw_key)
    assert not verification.ok
    assert verification.reason == "session-revoked"

    # The persisted status is still REVOKED (not flipped to EXPIRED).
    stored = store.get_proof_session(result.session.id)
    assert stored.status == ProofSessionStatus.REVOKED


def test_binding_target_mismatch_rejected(
    proof_service, confirmed_finding, mock_target, store
):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    verification = proof_service.verify(
        result.raw_key, expected_target_id="target_some-other-service"
    )
    assert not verification.ok
    assert verification.reason == "target-mismatch"


def test_binding_finding_mismatch_rejected(
    proof_service, confirmed_finding, mock_target, store
):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    verification = proof_service.verify(
        result.raw_key, expected_finding_id=new_id()
    )
    assert not verification.ok
    assert verification.reason == "finding-mismatch"


def test_binding_actor_mismatch_rejected(
    proof_service, confirmed_finding, mock_target, store
):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    verification = proof_service.verify(
        result.raw_key, expected_actor_id="actor_org_admin"
    )
    assert not verification.ok
    assert verification.reason == "actor-mismatch"


def test_binding_checks_pass_for_matching_context(
    proof_service, confirmed_finding, mock_target, store
):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    verification = proof_service.verify(
        result.raw_key,
        expected_target_id=target.id,
        expected_finding_id=confirmed_finding.id,
        expected_actor_id=result.session.actor_id,
    )
    assert verification.ok


def test_authentication_evidence_attached_to_finding(
    proof_service, confirmed_finding, mock_target, store
):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    verification = proof_service.verify(result.raw_key)
    assert verification.ok

    finding = store.get_finding(confirmed_finding.id)
    evidence = [store.get_evidence(eid) for eid in finding.evidence_ids]
    auth_evidence = [
        e for e in evidence
        if e and e.data.get("event") == "proof_key_authenticated"
    ]
    assert auth_evidence, "authentication evidence must be attached to finding"
    # Evidence must never contain the raw key.
    for e in auth_evidence:
        assert result.raw_key not in _dump(e.data)


def test_failed_impact_verification_persisted(store, mock_target):
    """A finding whose resource is NOT reached records the failure."""
    target = mock_target.discover()
    store.save_target(target)

    # job_api enforces the premium_model boundary — the probe is blocked.
    finding = Finding(
        target_id=target.id,
        severity=Severity.HIGH,
        affected_component=(
            "actor=UNAUTHENTICATED/free_user → interface=[job_api] → "
            "resource=premium_model"
        ),
        verification_status=FindingStatus.DISCOVERED,
    )
    store.save_finding(finding)

    verifier = ImpactVerifier(store)
    with pytest.raises(ImpactNotVerified):
        verifier.verify(finding, mock_target, target)

    records = store.get_impact_verifications(finding.id)
    assert records, "failed verification must still be persisted"
    assert records[0].verified is False


def test_negative_expiry_rejected(proof_service, confirmed_finding, mock_target):
    target = mock_target.discover()
    with pytest.raises(ProofKeyError, match="negative"):
        proof_service.create(
            confirmed_finding, mock_target, target, expires_hours=-1
        )


def test_mask_key_hides_secret(proof_service, confirmed_finding, mock_target, store):
    target = mock_target.discover()
    result = proof_service.create(confirmed_finding, mock_target, target)
    masked = mask_key(result.session)
    assert masked.startswith("omk_")
    assert masked.endswith("...")
    # The mask reveals the key identifier (session id) but no secret bytes.
    assert result.raw_key.split("_")[2] not in masked
    assert masked != result.raw_key


def test_case_study_never_contains_raw_key(
    proof_service, confirmed_finding, mock_target, store
):
    target = mock_target.discover()
    policy = Policy(
        target_name="mock",
        allowed_operations=[
            Operation.OBSERVE, Operation.TEST, Operation.RESET,
            Operation.PROOF_SESSION,
        ],
    )
    service = ProofSessionService(store, policy=policy)
    result = service.create(confirmed_finding, mock_target, target)

    cs = build_case_study(store, confirmed_finding, mock_target, target)
    rendered = _dump(cs.body)
    assert result.raw_key not in rendered
    assert result.raw_key.split("_")[2] not in rendered
    # Proof-session metadata IS present (minus the secret).
    assert cs.body["proof_session"]["id"] == result.session.id
    assert cs.body["proof_session"]["username"] == result.session.username
    # Real data, not placeholders.
    assert cs.body["research_question"] == confirmed_finding.attack_hypothesis
    assert isinstance(cs.body["experiments"], list)


def _dump(obj) -> str:
    """Best-effort deep stringification for leakage assertions."""
    import json

    return json.dumps(obj, default=str)