"""Policy enforcer — the runtime gate between intent and action."""

from __future__ import annotations

from opensystem.models import Target
from opensystem.policy.models import Operation, Policy


class PolicyViolation(Exception):
    """Raised when an operation is not permitted by the active policy."""

    def __init__(self, operation: Operation, policy: Policy) -> None:
        self.operation = operation
        self.policy = policy
        super().__init__(
            f"Policy violation: operation '{operation.value}' is not allowed "
            f"by policy for target '{policy.target_name}'. "
            f"Allowed: {[o.value for o in policy.allowed_operations]}"
        )


class PolicyEnforcer:
    """Checks every operation against the active policy before it runs."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def check(self, operation: Operation, target: Target | None = None) -> None:
        """Raise PolicyViolation if the operation is not permitted."""
        if target is not None:
            matches = self._policy.target_name in (
                "*",
                target.name,
                target.adapter,
            )
            if not matches:
                raise PolicyViolation(operation, self._policy)
        if not self._policy.allows(operation):
            raise PolicyViolation(operation, self._policy)

    def is_exhausted(self, rounds: int, experiments: int) -> bool:
        """Return True if the policy says the session must stop."""
        return (
            rounds >= self._policy.max_rounds
            or experiments >= self._policy.max_experiments
        )