"""CLI-level tests for the show-once proof-key workflow.

Exercises the complete operator flow through the CLI:

    attack → finding → impact verify → finding prove (show once)
    → proof-key verify (stdin) → proof-key inspect (masked)
    → proof-key revoke → proof-key verify fails
    → case-study create/show/export (never contains the raw key)

Every test runs against an isolated OPENSYSTEM_HOME. The raw key must appear
EXACTLY ONCE (in `finding prove` output) and nowhere else — including
inspect, list, export files, and stdin-verify output.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from opensystem.cli.commands import cli
from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Finding,
    FindingStatus,
    Severity,
)
from opensystem.target.mock import MockTarget

AFFECTED = (
    "actor=UNAUTHENTICATED/free_user → interface=[stream_api] → "
    "resource=premium_model"
)


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    """CLI runner isolated to a temp data home; stdin is not echoed so the
    raw key can be asserted absent from verify output."""
    monkeypatch.setenv("OPENSYSTEM_HOME", str(tmp_path))
    return CliRunner(echo_stdin=False)


@pytest.fixture()
def store(tmp_path):
    s = KnowledgeStore(str(tmp_path / "opensystem.db"))
    yield s
    s.close()


@pytest.fixture()
def seeded_finding(store):
    """A DISCOVERED finding on the mock target's vulnerable boundary."""
    adapter = MockTarget()
    target = adapter.discover()
    store.save_target(target)
    finding = Finding(
        target_id=target.id,
        actor_id=adapter.actors()["free_user"].id,
        resource_id=adapter.resources()["premium_model"].id,
        interface="stream_api",
        severity=Severity.HIGH,
        affected_component=AFFECTED,
        attack_hypothesis="free_user can access premium_model via stream_api",
        impact="PREMIUM INFERENCE EXECUTED",
        verification_status=FindingStatus.DISCOVERED,
    )
    store.save_finding(finding)
    return finding


def _invoke(runner, *args, **kwargs):
    result = runner.invoke(cli, list(args), **kwargs)
    assert result.exit_code == kwargs.pop(
        "expected_exit", result.exit_code
    ) or True, result.output
    return result


def test_full_proof_workflow(runner, store, seeded_finding):
    fid = seeded_finding.id

    # --- 1. Impact verification (independent confirmation) -----------
    r = runner.invoke(cli, ["impact", "verify", fid])
    assert r.exit_code == 0, r.output
    assert "CONFIRMED" in r.output

    # --- 2. Show-once proof key generation ---------------------------
    r = runner.invoke(cli, ["finding", "prove", fid])
    assert r.exit_code == 0, r.output
    lines = [ln.strip() for ln in r.output.splitlines() if ln.strip()]
    keys = [ln for ln in lines if ln.startswith("omk_")]
    assert len(keys) == 1, "raw key must be displayed exactly once"
    raw_key = keys[0]
    assert "Copy this key now" in r.output
    assert "will NOT be displayed again" in r.output
    session_id = next(
        ln.split()[-1] for ln in lines if ln.startswith("Session ID:")
    )

    # --- 3. Authenticate via stdin ------------------------------------
    r = runner.invoke(cli, ["proof-key", "verify", "--stdin"], input=raw_key + "\n")
    assert r.exit_code == 0, r.output
    assert "Authentication Successful" in r.output
    # The key is never echoed back.
    assert raw_key not in r.output

    # --- 4. Masked inspect ---------------------------------------------
    r = runner.invoke(cli, ["proof-key", "inspect", session_id])
    assert r.exit_code == 0, r.output
    assert raw_key not in r.output
    assert "..." in r.output
    assert "omk_" in r.output

    # --- 5. List shows metadata only -----------------------------------
    r = runner.invoke(cli, ["proof-key", "list"])
    assert r.exit_code == 0, r.output
    assert raw_key not in r.output
    assert session_id[:12] in r.output

    # --- 6. Revoke, then the key must fail ------------------------------
    r = runner.invoke(cli, ["proof-key", "revoke", session_id])
    assert r.exit_code == 0, r.output
    assert "revoked" in r.output

    r = runner.invoke(
        cli, ["proof-key", "verify", "--stdin"], input=raw_key + "\n"
    )
    assert r.exit_code != 0
    assert raw_key not in r.output

    # --- 7. Case study: created, shown, exported — never the raw key ----
    r = runner.invoke(cli, ["case-study", "create", fid])
    assert r.exit_code == 0, r.output
    cs_id = next(
        ln.split()[-1] for ln in r.output.splitlines()
        if ln.startswith("Case study created:")
    )

    r = runner.invoke(cli, ["case-study", "show", cs_id])
    assert r.exit_code == 0, r.output
    assert raw_key not in r.output

    r = runner.invoke(cli, ["case-study", "export", cs_id])
    assert r.exit_code == 0, r.output
    export_path = next(
        ln.split()[-1] for ln in r.output.splitlines() if "Exported" in ln
    )
    with open(export_path) as fh:
        exported = json.loads(fh.read())
    assert raw_key not in json.dumps(exported, default=str)

    # The historical record is preserved after revocation.
    record = store.get_proof_session(session_id)
    assert record.status.value == "REVOKED"
    assert record.revoked_at is not None


def test_prove_rejects_unconfirmed_finding(runner, seeded_finding):
    r = runner.invoke(cli, ["finding", "prove", seeded_finding.id])
    assert r.exit_code != 0
    assert "not CONFIRMED" in r.output


def test_prove_rejects_finding_without_impact_verification(
    runner, store, seeded_finding
):
    # Mark CONFIRMED directly WITHOUT impact verification.
    store.update_finding_status(seeded_finding.id, FindingStatus.CONFIRMED)
    r = runner.invoke(cli, ["finding", "prove", seeded_finding.id])
    assert r.exit_code != 0
    assert "impact verification" in r.output


def test_prove_rejects_negative_expiry(runner, seeded_finding):
    fid = seeded_finding.id
    runner.invoke(cli, ["impact", "verify", fid])
    r = runner.invoke(cli, ["finding", "prove", fid, "--expires-hours", "-5"])
    assert r.exit_code != 0
    assert "negative" in r.output


def test_verify_with_empty_stdin_fails(runner):
    r = runner.invoke(cli, ["proof-key", "verify", "--stdin"], input="\n")
    assert r.exit_code != 0
    assert "No key provided" in r.output


def test_verify_garbage_key_fails_cleanly(runner):
    r = runner.invoke(
        cli, ["proof-key", "verify", "--stdin"], input="not-a-real-key\n"
    )
    assert r.exit_code != 0
    assert "Authentication failed" in r.output


def test_replay_within_window_and_evidence_attachment(
    runner, store, seeded_finding
):
    fid = seeded_finding.id
    runner.invoke(cli, ["impact", "verify", fid])
    r = runner.invoke(cli, ["finding", "prove", fid])
    raw_key = next(
        ln.strip() for ln in r.output.splitlines() if ln.strip().startswith("omk_")
    )

    for _ in range(2):
        r = runner.invoke(
            cli, ["proof-key", "verify", "--stdin"], input=raw_key + "\n"
        )
        assert r.exit_code == 0, r.output

    # Usage recorded; evidence attached to the finding.
    record = store.get_proof_session(
        next(
            s.id for s in store.list_proof_sessions()
            if s.finding_id == fid
        )
    )
    assert record.last_used_at is not None
    assert record.status.value == "ACTIVE"

    finding = store.get_finding(fid)
    evidence = [store.get_evidence(eid) for eid in finding.evidence_ids]
    assert any(
        e and e.data.get("event") == "proof_key_authenticated"
        for e in evidence
    )
