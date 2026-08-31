"""Tests for the evolution engine."""

from __future__ import annotations

from opensystem.evolution.engine import EvolutionEngine
from opensystem.models import (
    EvolutionTrigger,
    Experiment,
    Hypothesis,
    HypothesisStatus,
    TestOutcome,
    TestSpec,
)


def _make_experiment(store, outcome=TestOutcome.SUCCESS, target_id="t1"):
    hyp = Hypothesis(
        target_id=target_id,
        statement="x",
        origin="strategy:http-sensitive-paths",
    )
    store.save_hypothesis(hyp)
    exp = Experiment(
        hypothesis_id=hyp.id,
        target_id=target_id,
        opensystem_version="0.4.0",
        test=TestSpec(name="t", parameters={"weakness": "http-sensitive-paths"}),
        outcome=outcome,
        observed_result="r",
    )
    store.save_experiment(exp)
    return hyp, exp


def test_evolution_on_success_records_strategy(store):
    engine = EvolutionEngine(store)
    hyp, exp = _make_experiment(store, TestOutcome.SUCCESS)
    event = engine.on_experiment(exp)
    assert event is not None
    assert event.trigger == EvolutionTrigger.ATTACK_SUCCESS
    assert event.from_hypothesis_id == hyp.id

    strategies = store.search_knowledge("SUCCESSFUL_STRATEGY")
    assert len(strategies) == 1


def test_evolution_on_failure_records_failed_strategy(store):
    engine = EvolutionEngine(store)
    _, exp = _make_experiment(store, TestOutcome.FAILURE)
    event = engine.on_experiment(exp)
    assert event is not None
    assert event.trigger == EvolutionTrigger.ATTACK_FAILURE

    failed = store.search_knowledge("FAILED_STRATEGY")
    assert len(failed) == 1


def test_evolution_no_event_for_inconclusive(store):
    engine = EvolutionEngine(store)
    _, exp = _make_experiment(store, TestOutcome.INCONCLUSIVE)
    assert engine.on_experiment(exp) is None


def test_next_hypothesis_after_block(store):
    engine = EvolutionEngine(store)
    hyp, _ = _make_experiment(store, TestOutcome.FAILURE)

    next_hyp = engine.next_hypothesis(
        hyp, ["http-server-disclosure", "http-dir-listing"]
    )
    assert next_hyp is not None
    assert next_hyp.parent_id == hyp.id
    assert next_hyp.origin == "strategy:http-server-disclosure"
    assert "blocked" in next_hyp.statement

    events = store.list_evolution_events()
    assert len(events) == 1
    assert events[0].to_hypothesis_id == next_hyp.id


def test_next_hypothesis_skips_already_tested(store):
    engine = EvolutionEngine(store)
    hyp, _ = _make_experiment(store, TestOutcome.FAILURE)

    # Both candidates already tested.
    other = Hypothesis(
        target_id="t1", statement="y", origin="strategy:http-server-disclosure"
    )
    store.save_hypothesis(other)
    store.update_hypothesis_status(other.id, HypothesisStatus.REJECTED)

    next_hyp = engine.next_hypothesis(
        hyp, ["http-server-disclosure", "http-dir-listing"]
    )
    assert next_hyp is not None
    assert next_hyp.origin == "strategy:http-dir-listing"