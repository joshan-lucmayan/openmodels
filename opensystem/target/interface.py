"""The generic target abstraction (Phase 5).

OpenSystem must NOT be architecturally limited to any single technology. Every
target implements a common interface so the adversarial reasoning engine can
operate against web applications, APIs, identity systems, AI/agent systems,
distributed systems, simulations, and more — without changing the core.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import Enum
from typing import Any

from opensystem.models import (
    Evidence,
    Observation,
    Target,
    TestResult,
    TestSpec,
)


class Capability(str, Enum):
    """Optional adapter capabilities beyond the required TargetAdapter contract.

    An adapter declares the optional capabilities it genuinely implements via
    its ``capabilities`` attribute. Callers must check declaration instead of
    probing for methods: a declared-but-missing method is an adapter contract
    violation (a bug), while an undeclared capability is simply unsupported.
    """

    TEST_PLANNING = "test_planning"
    """plan_test() — translate a Hypothesis into a concrete, adapter-specific
    TestSpec. Adapters that require protocol-specific test parameters
    declare this; the experiment engine delegates TestSpec construction to
    them instead of assuming the mock weakness model."""

    DISCOVERY = "discovery"
    """describe_interfaces / describe_resources / describe_actors /
    describe_auth_states / describe_transitions."""


class AdapterCapabilityError(Exception):
    """An adapter declares a capability but does not implement it correctly.

    This is an adapter bug and must surface loudly; it must never be
    interpreted as "capability unsupported".
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

    Optional capabilities are declared in ``capabilities`` and resolved via
    :func:`adapter_capability` — never by probing for method existence.
    """

    name: str = "base"

    capabilities: frozenset[Capability] = frozenset()

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


def adapter_supports(adapter: TargetAdapter, capability: Capability) -> bool:
    """Return True if the adapter declares the capability."""
    return capability in getattr(adapter, "capabilities", frozenset())


def adapter_capability(
    adapter: TargetAdapter, capability: Capability, method_name: str
) -> Callable | None:
    """Return the bound method implementing a declared capability.

    Returns None if the adapter does not declare the capability. Raises
    AdapterCapabilityError if the capability IS declared but the implementing
    method is missing or not callable. Exceptions raised by the method itself
    propagate to the caller — a broken implementation must not be mistaken
    for a missing capability.
    """
    if not adapter_supports(adapter, capability):
        return None
    method: Any = getattr(adapter, method_name, None)
    if not callable(method):
        raise AdapterCapabilityError(
            f"Adapter '{getattr(adapter, 'name', type(adapter).__name__)}' "
            f"declares capability '{capability.value}' but does not "
            f"implement {method_name}()."
        )
    return method
