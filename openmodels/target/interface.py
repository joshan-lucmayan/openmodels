"""The generic target abstraction (Phase 5).

OpenModels must NOT be architecturally limited to any single technology. Every
target implements a common interface so the adversarial reasoning engine can
operate against web applications, APIs, identity systems, AI/agent systems,
distributed systems, simulations, and more — without changing the core.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from openmodels.models import (
    Observation,
    Target,
    TestResult,
    TestSpec,
    Evidence,
)


class TargetDescription(dict):
    """Human-readable summary of a target's current state.

    A plain dict subclass to keep the adapter protocol dependency-light; a
    future adapter may return richer structured descriptions.
    """


class TargetAdapter(ABC):
    """Common interface every target adapter must implement.

    Responsibilities
    -----------------
    discover()        -- build/load the initial Target model (identity,
                         interfaces, assets, trust boundaries, rules)
    observe()         -- return current observations from the target
    describe()        -- return a structured description of the target
    execute_test()    -- execute a single TestSpec and return a TestResult
    collect_evidence()-- gather evidence supporting the last executed test
    reset()           -- return the target to a known, authorized state
    """

    name: str = "base"

    @abstractmethod
    def discover(self) -> Target: ...

    @abstractmethod
    def observe(self) -> list[Observation]: ...

    @abstractmethod
    def describe(self) -> dict: ...

    @abstractmethod
    def execute_test(self, test: TestSpec) -> TestResult: ...

    @abstractmethod
    def collect_evidence(self) -> list[Evidence]: ...

    @abstractmethod
    def reset(self) -> None: ...
