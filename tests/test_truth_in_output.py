"""Truth-in-output tests: CLI and case-study claims must match the evidence."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from opensystem.cli.commands import _regression_summary, cli
from opensystem.impact.engine import ImpactNotVerified, ImpactVerifier
from opensystem.models import (
    Finding,
    Regression,
    TestOutcome,
)
from opensystem.proof.service import build_case_study

# --------------------------------------------------------------------------- #
# Phase: derived regression claims (security-test output)
# --------------------------------------------------------------------------- #

def _reg(outcome: TestOutcome) -> Regression:
    return Regression(
        defense_id="d1", hypothesis_id="h1", target_id="t1", outcome=outcome
    )


def test_regression_summary_all_blocked():
    summary = _regression_summary(
        [_reg(TestOutcome.FAILURE), _reg(TestOutcome.FAILURE)]
    )
    assert summary == "Regressions: 2 re-tests, 2 blocked"


def test_regression_summary_reports_still_exploitable():
    summary = _regression_summary(
        [_reg(TestOutcome.FAILURE), _reg(TestOutcome.SUCCESS)]
    )
    assert "1 blocked" in summary
    assert "1 STILL EXPLOITABLE" in summary
    assert "defenses held" not in summary


def test_regression_summary_reports_inconclusive():
    summary = _regression_summary(
        [_reg(TestOutcome.INCONCLUSIVE), _reg(TestOutcome.ERROR)]
    )
    assert "0 blocked" in summary
    assert "2 inconclusive" in summary


def test_security_test_cli_reports_derived_regressions(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENSYSTEM_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(cli, ["security-test", "mock", "--rounds", "5"])
    assert result.exit_code == 0, result.output

    # The hardcoded claim is gone; the summary is derived from the records.
    assert "all blocked (defenses held)" not in result.output
    assert "Regressions: 5 re-tests, 5 blocked" in result.output
    assert "STILL EXPLOITABLE" not in result.output


# --------------------------------------------------------------------------- #
# Phase: case-study verification truthfulness
# --------------------------------------------------------------------------- #

def _finding(store, mock_target, interface="stream_api") -> Finding:
    target = mock_target.discover()
    store.save_target(target)
    finding = Finding(
        target_id=target.id,
        actor_id=mock_target.actors()["free_user"].id,
        resource_id=mock_target.resources()["premium_model"].id,
        interface=interface,
        affected_component=(
            "actor=FREE_USER/free_user → interface="
            f"[{interface}] → resource=premium_model"
        ),
    )
    store.save_finding(finding)
    return finding


def test_case_study_without_verification_claims_unknown(store, mock_target):
    finding = _finding(store, mock_target)
    cs = build_case_study(store, finding, mock_target, mock_target.discover())

    assert cs.body["impact_verification"]["status"] == "unknown"
    assert "Impact verification status: unknown" in cs.body["conclusion"]
    assert "Impact independently verified:" not in cs.body["conclusion"]


def test_case_study_failed_verification_is_reported(store, mock_target):
    """A blocked boundary probe must be reported as NOT verified."""
    # chat_api enforces the premium_model boundary — the probe is blocked.
    finding = _finding(store, mock_target, interface="chat_api")
    with pytest.raises(ImpactNotVerified):
        ImpactVerifier(store).verify(
            finding, mock_target, mock_target.discover()
        )

    cs = build_case_study(store, finding, mock_target, mock_target.discover())
    assert cs.body["impact_verification"]["status"] == "not_verified"
    assert "did NOT confirm" in cs.body["impact_verification"]["summary"]
    assert "Impact verification status: not_verified" in cs.body["conclusion"]


def test_case_study_verified_status_is_recorded(store, mock_target):
    finding = _finding(store, mock_target, interface="stream_api")
    verification = ImpactVerifier(store).verify(
        finding, mock_target, mock_target.discover()
    )
    assert verification.verified

    cs = build_case_study(store, finding, mock_target, mock_target.discover())
    assert cs.body["impact_verification"]["status"] == "verified"
    assert "Impact verification status: verified" in cs.body["conclusion"]


def test_cli_case_study_requires_confirmed_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENSYSTEM_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["init"])

    # Seed a DISCOVERED finding directly in the CLI's store.
    from opensystem.knowledge.store import KnowledgeStore
    from opensystem.models import FindingStatus, Severity
    from opensystem.target.mock import MockTarget

    adapter = MockTarget()
    target = adapter.discover()
    store = KnowledgeStore(str(tmp_path / "opensystem.db"))
    store.save_target(target)
    finding = Finding(
        target_id=target.id,
        actor_id=adapter.actors()["free_user"].id,
        resource_id=adapter.resources()["premium_model"].id,
        interface="stream_api",
        severity=Severity.HIGH,
        verification_status=FindingStatus.DISCOVERED,
    )
    store.save_finding(finding)
    store.close()

    result = runner.invoke(cli, ["case-study", "create", finding.id])
    assert result.exit_code == 1
    assert "not CONFIRMED" in result.output


def test_defense_record_states_when_defense_not_applicable(store, mock_target):
    """A defense the target cannot apply must not be recorded as applied."""
    from opensystem.attack.planner import default_planner
    from opensystem.core.engine import AdversarialEngine
    from opensystem.models import Finding, FindingStatus

    target = mock_target.discover()
    store.save_target(target)
    # A campaign-style finding has no matching mock weakness key, so the
    # target cannot actually defend it.
    finding = Finding(
        target_id=target.id,
        affected_component="actor=GUEST/guest → interface=[stream_api] → resource=premium_model",
    )
    store.save_finding(finding)

    engine = AdversarialEngine(store=store, planner=default_planner(store))
    defense = engine._apply_defense(mock_target, finding)

    assert "not applicable" in defense.description
    assert "Defense applied" not in defense.description
    assert store.get_finding(finding.id).verification_status == (
        FindingStatus.DISCOVERED
    )


def test_defense_record_reports_applied_defense(store, mock_target):
    from opensystem.attack.planner import default_planner
    from opensystem.core.engine import AdversarialEngine
    from opensystem.models import Finding, FindingStatus

    target = mock_target.discover()
    store.save_target(target)
    finding = Finding(target_id=target.id, affected_component="auth-bypass")
    store.save_finding(finding)

    engine = AdversarialEngine(store=store, planner=default_planner(store))
    defense = engine._apply_defense(mock_target, finding)

    assert defense.description == "Defense applied for auth-bypass."
    assert store.get_finding(finding.id).verification_status == (
        FindingStatus.MITIGATION
    )
