"""Tests for the enforced --stop-on-finding policy.

The flag must actually stop research at the first finding, persist the state
of everything already done, and do no further testing afterwards.
"""

from __future__ import annotations

from opensystem.attack.planner import default_planner
from opensystem.core.engine import AdversarialEngine
from opensystem.models import HypothesisStatus
from opensystem.policy.models import Policy


def _engine(store, http_target, **policy_updates) -> AdversarialEngine:
    target_model = http_target.discover()
    policy = Policy(
        target_name=target_model.adapter,
        environment=target_model.environment,
        scope=target_model.scope,
        max_rounds=20,
        max_experiments=100,
        **policy_updates,
    )
    return AdversarialEngine(
        store=store, policy=policy, planner=default_planner(store)
    )


def test_research_continues_when_flag_disabled(store, http_target):
    engine = _engine(store, http_target)
    report = engine.research(http_target, rounds=11)
    assert report.findings_created > 1
    assert report.stopped_reason == "MAX_ROUNDS"


def test_research_stops_after_first_finding(store, http_target):
    engine = _engine(store, http_target, stop_on_finding=True)
    report = engine.research(http_target, rounds=11)
    assert report.findings_created == 1
    assert report.experiments_run == 1
    assert report.stopped_reason == "FINDING_STOP"


def test_state_persisted_after_finding_stop(store, http_target):
    engine = _engine(store, http_target, stop_on_finding=True)
    target_model = http_target.discover()
    report = engine.research(http_target, rounds=11)

    experiments = store.list_experiments(target_model.id)
    assert len(experiments) == report.experiments_run == 1

    hypotheses = store.list_hypotheses(target_model.id)
    accepted = [h for h in hypotheses if h.status == HypothesisStatus.ACCEPTED]
    proposed = [h for h in hypotheses if h.status == HypothesisStatus.PROPOSED]
    assert len(accepted) == 1
    assert len(proposed) == len(hypotheses) - 1


def test_no_further_experiments_after_stop(store, http_target):
    engine = _engine(store, http_target, stop_on_finding=True)
    target_model = http_target.discover()
    engine.research(http_target, rounds=11)

    # One SUCCESS evolution event for the completed experiment, no failure
    # events: nothing ran after the stop.
    events = store.list_evolution_events(target_model.id)
    assert len(events) == 1


def test_finding_stop_respects_stop_reason_over_no_more_hypotheses(
    store, http_target
):
    """A finding stop is reported as such even when the queue is exhausted."""
    engine = _engine(store, http_target, stop_on_finding=True)
    report = engine.research(http_target, rounds=1)
    assert report.stopped_reason == "FINDING_STOP"
    assert report.findings_created == 1