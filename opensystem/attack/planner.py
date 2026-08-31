"""Attack planner — converts knowledge into hypotheses and test plans.

The planner is deliberately a *strategy* system rather than a hardcoded list of
attacks. New attack families are added by registering new strategies, keeping
the core engine unchanged. This keeps OpenSystem extensible for future research
modules (web/API, identity, AI/agent, logic, etc.) without redesigning the core.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from opensystem.models import (
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
    # Each hypothesis generated carries origin="strategy:<name>"; adapters
    # translate that origin into a concrete test (mock: weakness key,
    # http: protocol test, …).
    weakness_key: str | None = None
    # Restrict the strategy to specific target adapters (None = any).
    applies_to: tuple[str, ...] | None = None


@dataclass
class AttackPlanner:
    """Holds strategies and generates hypotheses for a target.

    The initial strategy set is small and deterministic (see HTTP_STRATEGIES).
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
            if (
                strategy.applies_to is not None
                and target.adapter not in strategy.applies_to
            ):
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
            # A registered factory that raises is an implementation error and
            # propagates — it must not silently disappear from the plan.
            generated = factory(target, observations, self.store)
            for h in generated:
                if h.statement in existing_statements:
                    continue
                hypotheses.append(h)

        return hypotheses[:limit]


# --------------------------------------------------------------------------- #
# HTTP(S) strategy set — real web application tests (live targets).
# --------------------------------------------------------------------------- #

HTTP_STRATEGIES: list[AttackStrategy] = [
    AttackStrategy(
        name="http-security-headers",
        family="http-headers",
        description="Test whether baseline security headers are missing.",
        weakness_key="http-security-headers",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-server-disclosure",
        family="information-disclosure",
        description="Test whether server software versions are disclosed.",
        weakness_key="http-server-disclosure",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-dir-listing",
        family="information-disclosure",
        description="Test whether directory listing (autoindex) is enabled.",
        weakness_key="http-dir-listing",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-sensitive-paths",
        family="information-disclosure",
        description="Test whether sensitive files (.git, .env, backups) are exposed.",
        weakness_key="http-sensitive-paths",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-methods",
        family="http-configuration",
        description="Test whether dangerous HTTP methods are allowed.",
        weakness_key="http-methods",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-cors",
        family="http-configuration",
        description="Test whether CORS reflects arbitrary origins.",
        weakness_key="http-cors",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-cookie-flags",
        family="session-management",
        description="Test whether session cookies lack Secure/HttpOnly flags.",
        weakness_key="http-cookie-flags",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-open-redirect",
        family="input-validation",
        description="Test whether common redirect parameters allow external redirects.",
        weakness_key="http-open-redirect",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-admin-exposure",
        family="authorization",
        description="Test whether admin interfaces are reachable without authentication.",
        weakness_key="http-admin-exposure",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-error-disclosure",
        family="information-disclosure",
        description="Test whether error pages disclose stack traces.",
        weakness_key="http-error-disclosure",
        applies_to=("http",),
    ),
    AttackStrategy(
        name="http-tls",
        family="transport-security",
        description="Test whether transport security (TLS/HSTS) is weak.",
        weakness_key="http-tls",
        applies_to=("http",),
    ),
]


def default_planner(store: object) -> AttackPlanner:
    """Create an AttackPlanner with the built-in HTTP strategy set."""
    planner = AttackPlanner(store=store)
    for strategy in HTTP_STRATEGIES:
        planner.register_strategy(strategy)
    return planner
