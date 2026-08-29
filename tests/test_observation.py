"""Tests for observation persistence."""

from __future__ import annotations

from opensystem.observation.engine import ObservationEngine
from opensystem.target.mock import MockTarget


def test_observations_persist_to_store(store):
    target = MockTarget()
    engine = ObservationEngine(store)
    target_model = target.discover()
    obs = engine.observe(target, target_id=target_model.id)
    assert len(obs) >= 5

    persisted = store.list_observations(target_model.id)
    assert len(persisted) == len(obs)


def test_observation_target_id_stamped(store):
    target = MockTarget()
    engine = ObservationEngine(store)
    target_model = target.discover()
    engine.observe(target, target_id=target_model.id)
    persisted = store.list_observations(target_model.id)
    assert all(o.target_id == target_model.id for o in persisted)


def test_defense_observation_recorded(store):
    target = MockTarget()
    target_model = target.discover()
    store.save_target(target_model)
    target.defend("auth-bypass", note="rotated credential")

    obs_engine = ObservationEngine(store)
    obs = obs_engine.observe(target, target_id=target_model.id)
    events = [o for o in obs if o.data.get("event") == "defense_applied"]
    assert len(events) == 1
    assert events[0].data["weakness_key"] == "auth-bypass"
