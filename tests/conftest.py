"""Shared fixtures for OpenSystem tests."""

from __future__ import annotations

import pytest

from opensystem.attack.planner import default_planner
from opensystem.core.engine import AdversarialEngine
from opensystem.knowledge.store import KnowledgeStore
from opensystem.policy.models import Policy
from opensystem.target.mock import MockTarget


@pytest.fixture()
def store(tmp_path):
    """A fresh in-temp-dir knowledge store for each test."""
    s = KnowledgeStore(str(tmp_path / "test.db"))
    yield s
    s.close()


@pytest.fixture()
def mock_target() -> MockTarget:
    return MockTarget()


@pytest.fixture()
def policy() -> Policy:
    return Policy(target_name="mock", max_rounds=20, max_experiments=100)


@pytest.fixture()
def engine(store, policy) -> AdversarialEngine:
    return AdversarialEngine(store=store, policy=policy, planner=default_planner(store))
