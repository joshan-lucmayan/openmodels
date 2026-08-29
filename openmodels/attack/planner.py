"""Attack planner — converts knowledge into hypotheses and test plans.

The planner is deliberately a *strategy* system rather than a hardcoded list of
attacks. New attack families are added by registering new strategies, keeping
the core engine unchanged. This keeps OpenModels extensible for future research
modules (web/API, identity, AI/agent, logic, etc.) without redesigning the core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from openmodels.models import (
    Hypothesis,
    HypothesisStatus,
    Observation,
    Target,
)


@dataclass(frozen=True)
class AttackStrategy:
    """A named attack family that generates hypotheses from observations."""

    name: str
    family: str
    description: str
    # Each hypothesis generated carries origin="strategy:<name>"; the mock
    # target uses that origin to map to a weakness key.
    weakness_key: str | None = None


@dataclass
class AttackPlanner:
    """Holds strategies and generates hypotheses for a target.

    The initial strategy set is small and deterministic (see STRATEGIES).
    Future phases plug in richer hypothesis generators behind the same
    interface (e.g. an LLM-backed reasoner or a cross-component analyzer),
    while keeping the core loop unchanged.
    """

    store: object  # KnowledgeStore
    strategies: dict[str, AttackStrategy] = field(default_factory=dict)
    strategy_factories: dict[str, Callable] = field(default_factory=dict)

    def register_strategy(self, strategy: AttackStrategy) -> None:
        self.strategies[strategy.name] = strategy

    def register_factory(self, name: str, factory: Callable) -> None:
        """Register a hypothesis factory that returns one or more hypotheses.

        A factory receives (target_model, observations, knowledge) and returns
        a list of Hypothesis. This is the extension point for future
        reasoning-based planners.
        """
        self.strategy_factories[name] = factory

    def list_strategies(self) -> list[AttackStrategy]:
        return list(self.strategies.values())

    def generate_hypotheses(
        self,
        target: Target,
        observations: list[Observation],
        limit: int = 10,
    ) -> list[Hypothesis]:
        """Generate hypotheses for the target from all known strategies.

        Hypotheses for weaknesses already blocked (defense applied) are still
        generated — re-testing a blocked path is a regression check and yields
        valuable learning. Deduplication removes already-accepted hypotheses.
        """
        existing = self.store.list_hypotheses(target.id)
        existing_statements = {
            h.statement for h in existing
            if h.status == HypothesisStatus.ACCEPTED
        }

        hypotheses: list[Hypothesis] = []

        for strategy in self.strategies.values():
            if strategy.weakness_key is None:
                continue
            statement = f"can {strategy.weakness_key} be demonstrated as a weakness?"
            if statement in existing_statements:
                continue
            hypotheses.append(
                Hypothesis(
                    target_id=target.id,
                    statement=statement,
                    assumption=f"target assumes {strategy.weakness_key} is safe",
                    status=HypothesisStatus.PROPOSED,
                    origin=f"strategy:{strategy.weakness_key}",
                    confidence=0.7,
                )
            )

        for factory in self.strategy_factories.values():
            try:
                generated = factory(target, observations, self.store)
            except Exception:
                continue
            for h in generated:
                if h.statement in existing_statements:
                    continue
                hypotheses.append(h)

        return hypotheses[:limit]


# --------------------------------------------------------------------------- #
# Built-in strategy set.
# --------------------------------------------------------------------------- #

STRATEGIES: list[AttackStrategy] = [
    AttackStrategy(
        name="auth-bypass",
        family="authentication",
        description="Test whether authentication can be bypassed.",
        weakness_key="auth-bypass",
    ),
    AttackStrategy(
        name="authz-ownership",
        family="authorization",
        description="Test whether object ownership checks can be bypassed.",
        weakness_key="authz-ownership",
    ),
    AttackStrategy(
        name="input-traversal",
        family="input-validation",
        description="Test whether path traversal is possible.",
        weakness_key="input-traversal",
    ),
    AttackStrategy(
        name="resource-abuse",
        family="resource-usage",
        description="Test whether resources can be abused.",
        weakness_key="resource-abuse",
    ),
    AttackStrategy(
        name="agent-tool-boundary",
        family="ai-agent",
        description="Test whether an agent tool boundary can be escaped.",
        weakness_key="agent-tool-boundary",
    ),
    AttackStrategy(
        name="session-fixation",
        family="session-management",
        description="Test whether session ids can be fixed across auth.",
        weakness_key="session-fixation",
    ),
    AttackStrategy(
        name="state-transition",
        family="business-logic",
        description="Test whether illegal workflow state transitions are allowed.",
        weakness_key="state-transition",
    ),
    AttackStrategy(
        name="dependency-supply-chain",
        family="supply-chain",
        description="Test whether dependencies can be substituted.",
        weakness_key="dependency-supply-chain",
    ),
]


def default_planner(store: object) -> AttackPlanner:
    """Create an AttackPlanner with the built-in strategy set."""
    planner = AttackPlanner(store=store)
    for strategy in STRATEGIES:
        planner.register_strategy(strategy)
    return planner
