"""Tests for observation persistence."""

from __future__ import annotations

from opensystem.observation.engine import ObservationEngine


def test_observations_persist_to_store(store, http_target):
    engine = ObservationEngine(store)
    target_model = http_target.discover()
    obs = engine.observe(http_target, target_id=target_model.id)
    assert len(obs) >= 1

    persisted = store.list_observations(target_model.id)
    assert len(persisted) == len(obs)


def test_observation_target_id_stamped(store, http_target):
    engine = ObservationEngine(store)
    target_model = http_target.discover()
    engine.observe(http_target, target_id=target_model.id)
    persisted = store.list_observations(target_model.id)
    assert all(o.target_id == target_model.id for o in persisted)