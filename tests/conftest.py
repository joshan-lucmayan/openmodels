"""Shared fixtures for OpenModels tests."""

from __future__ import annotations

import pytest

from openmodels.attack.planner import default_planner
from openmodels.core.engine import AdversarialEngine
from openmodels.knowledge.store import KnowledgeStore
from openmodels.policy.models import Policy
from openmodels.target.mock import MockTarget


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
